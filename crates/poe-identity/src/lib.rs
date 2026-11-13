//! poe-identity — attested device identity (BUILD_FLOW Step 7).
//!
//! A machine earns only as **one attested device**: a manufacturer root,
//! admitted as a registry claim with a per-epoch quota, signs an
//! attestation over a device key; the device binds to exactly one
//! machine identity. The platform verifiers (Android StrongBox/KeyMint,
//! TPM 2.0, Apple Secure Enclave) differ per platform and live behind
//! the mobile shells; what is common — and what lives here — is the
//! verification and binding logic over the signed statement, in the
//! node's own signature scheme (ML-DSA-87 via poe-crypto).
//!
//! The clone defense is the binding table itself: cloned key material
//! presents the *same* device key, and a device key binds to one machine
//! — a second body presenting it under another machine is refused
//! (F-Clone), so two bodies cannot both earn from one identity.
//! Devices with no attesting hardware are **relay-only**: they may relay
//! and follow the chain, and they never earn.
//!
//! Revocation is two-level: a root can be revoked (every device under it
//! stops earning) and a single device can be revoked (its binding dies
//! with it).

use poe_crypto::hash::{h, Part};
use poe_crypto::pq::{dsa_verify, DsaKeypair};
use std::collections::{HashMap, HashSet};

/// A device's identity: derived from its public key, so the same key
/// material always names the same device — the clone has nowhere to hide.
pub fn device_id(device_pk: &[u8]) -> u64 {
    h("device-id", &[Part::Bytes(device_pk)])[0..8]
        .try_into()
        .map(u64::from_be_bytes)
        .unwrap_or(0)
}

/// A manufacturer's root, admitted with a per-epoch join quota.
#[derive(Clone, Debug)]
pub struct RootAdmission {
    pub root_id: u64,
    pub root_pk: Vec<u8>,
    pub quota_per_epoch: u64,
}

/// A signed attestation statement: this device key belongs to this root,
/// with this serial, until this epoch.
#[derive(Clone, Debug)]
pub struct Attestation {
    pub device_pk: Vec<u8>,
    pub root_id: u64,
    pub serial: u64,
    pub expiry_epoch: u64,
    pub signature: Vec<u8>,
}

impl Attestation {
    /// The bytes the root signs.
    pub fn statement(&self) -> [u8; 64] {
        h(
            "attestation",
            &[
                Part::Bytes(&self.device_pk),
                Part::Nat(self.root_id),
                Part::Nat(self.serial),
                Part::Nat(self.expiry_epoch),
            ],
        )
    }

    /// Issue an attestation (the manufacturer's side of the ceremony).
    pub fn issue(
        root: &DsaKeypair,
        rng: &mut rand::rngs::ThreadRng,
        device_pk: Vec<u8>,
        root_id: u64,
        serial: u64,
        expiry_epoch: u64,
    ) -> Attestation {
        let mut a = Attestation {
            device_pk,
            root_id,
            serial,
            expiry_epoch,
            signature: Vec::new(),
        };
        a.signature = root.sign(rng, &a.statement());
        a
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Attested: may bind, earn, vote, propose.
    Full,
    /// No attesting hardware: may relay and follow, never earns.
    RelayOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityError {
    UnknownRoot,
    RootRevoked,
    BadSignature,
    Expired,
    DeviceRevoked,
    QuotaExceeded,
    /// The F-Clone refusal: this device is already bound to another
    /// machine.
    CloneAttempt,
}

#[derive(Clone, Debug)]
struct DeviceRecord {
    machine: u64,
    root_id: u64,
}

#[derive(Default)]
pub struct IdentityRegistry {
    roots: HashMap<u64, RootAdmission>,
    revoked_roots: HashSet<u64>,
    devices: HashMap<u64, DeviceRecord>,
    revoked_devices: HashSet<u64>,
    epoch_joins: HashMap<(u64, u64), u64>,
}

impl IdentityRegistry {
    pub fn new() -> IdentityRegistry {
        IdentityRegistry::default()
    }

    /// Admit a manufacturer root (on-chain, this is an Admission-registry
    /// claim at genesis or by governance; here it is the state that claim
    /// maintains).
    pub fn admit_root(&mut self, root: RootAdmission) {
        self.roots.insert(root.root_id, root);
    }

    pub fn revoke_root(&mut self, root_id: u64) {
        self.revoked_roots.insert(root_id);
    }

    pub fn revoke_device(&mut self, device: u64) {
        self.revoked_devices.insert(device);
    }

    /// How a presenting device is classified: with a verifiable
    /// attestation it is full; without one it is relay-only.
    pub fn classify(&self, att: Option<&Attestation>, epoch: u64) -> Mode {
        match att {
            Some(a) if self.verify(a, epoch).is_ok() => Mode::Full,
            _ => Mode::RelayOnly,
        }
    }

    /// Verify an attestation's signature, root standing and expiry.
    pub fn verify(&self, att: &Attestation, epoch: u64) -> Result<u64, IdentityError> {
        let root = self.roots.get(&att.root_id).ok_or(IdentityError::UnknownRoot)?;
        if self.revoked_roots.contains(&att.root_id) {
            return Err(IdentityError::RootRevoked);
        }
        if epoch > att.expiry_epoch {
            return Err(IdentityError::Expired);
        }
        if !dsa_verify(&root.root_pk, &att.statement(), &att.signature) {
            return Err(IdentityError::BadSignature);
        }
        Ok(device_id(&att.device_pk))
    }

    /// Bind an attested device to a machine — the join's identity gate.
    /// Enforces, in order: the attestation itself, device revocation,
    /// the one-device-one-machine clone rule, and the root's quota for
    /// this epoch.
    pub fn bind(
        &mut self,
        att: &Attestation,
        machine: u64,
        epoch: u64,
    ) -> Result<u64, IdentityError> {
        let dev = self.verify(att, epoch)?;
        if self.revoked_devices.contains(&dev) {
            return Err(IdentityError::DeviceRevoked);
        }
        if let Some(rec) = self.devices.get(&dev) {
            if rec.machine != machine {
                return Err(IdentityError::CloneAttempt);
            }
            return Ok(dev); // the same body re-presenting: idempotent
        }
        let root = &self.roots[&att.root_id];
        let used = self.epoch_joins.entry((att.root_id, epoch)).or_insert(0);
        if *used >= root.quota_per_epoch {
            return Err(IdentityError::QuotaExceeded);
        }
        *used += 1;
        self.devices.insert(dev, DeviceRecord { machine, root_id: att.root_id });
        Ok(dev)
    }

    /// Whether a machine currently earns: it has a bound device whose
    /// root and device both stand unrevoked.
    pub fn can_earn(&self, machine: u64) -> bool {
        self.devices.iter().any(|(dev, rec)| {
            rec.machine == machine
                && !self.revoked_roots.contains(&rec.root_id)
                && !self.revoked_devices.contains(dev)
        })
    }

    /// Relaying is open to both modes — it is how relay-only devices
    /// stay useful without earning.
    pub fn may_relay(&self, _machine: u64) -> bool {
        true
    }
}
