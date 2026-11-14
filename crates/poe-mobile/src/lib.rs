//! Step 7 — the mobile shell core.
//!
//! What a PoE phone app actually needs from the Rust workspace is
//! small: hold the device identity key (ML-DSA), know its machine
//! id, and sign with the key (heartbeats, acts). Everything else —
//! the chain, finality, the wallet's ledger logic — either runs on
//! the node or belongs to later shell work. This crate exposes
//! exactly that surface through UniFFI so the Kotlin (Android) and
//! Swift (iOS) shells are thin UI over the same audited crypto the
//! node uses — never a reimplementation.
//!
//! Status (2026-11-14, recorded in this crate's README): the Rust
//! core builds and is unit-tested; Kotlin bindings are generated
//! and compile-checked on the JVM; Swift bindings are generated
//! (no Swift toolchain in the build environment). The app
//! scaffolds themselves (Android/iOS projects) are not part of
//! this crate.

use poe_crypto::pq::{dsa_verify, DsaKeypair};
use std::sync::{Arc, Mutex};

uniffi::setup_scaffolding!();

/// Why a device identity could not be restored from bytes.
#[derive(Debug, uniffi::Error)]
pub enum DeviceKeyError {
    /// The supplied bytes are not a valid ML-DSA keypair.
    InvalidKeyBytes,
}

impl std::fmt::Display for DeviceKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceKeyError::InvalidKeyBytes => write!(f, "not a valid device keypair"),
        }
    }
}

impl std::error::Error for DeviceKeyError {}

/// A device identity key, held by the phone. The keypair never
/// leaves the device except through `secret_key()` — the explicit
/// owner backup path.
#[derive(uniffi::Object)]
pub struct DeviceKey {
    inner: Mutex<DsaKeypair>,
}

#[uniffi::export]
impl DeviceKey {
    /// Generate a fresh device identity (ML-DSA, as registered by
    /// poe-identity).
    #[uniffi::constructor]
    pub fn generate() -> Arc<Self> {
        let mut rng = rand::thread_rng();
        Arc::new(DeviceKey { inner: Mutex::new(DsaKeypair::generate(&mut rng)) })
    }

    /// Restore a device identity from its exported key bytes.
    /// Fails with DeviceKeyError if the bytes are not a valid
    /// keypair.
    #[uniffi::constructor]
    pub fn from_bytes(
        public_key: Vec<u8>,
        secret_key: Vec<u8>,
    ) -> Result<Arc<Self>, DeviceKeyError> {
        DsaKeypair::from_key_bytes(&public_key, &secret_key)
            .map(|kp| Arc::new(DeviceKey { inner: Mutex::new(kp) }))
            .ok_or(DeviceKeyError::InvalidKeyBytes)
    }

    /// The device public key — what gets attested and registered.
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.lock().expect("device key lock").public_key_bytes()
    }

    /// The secret key bytes, for owner backup/export only.
    pub fn secret_key(&self) -> Vec<u8> {
        self.inner.lock().expect("device key lock").secret_key_bytes()
    }

    /// This device's machine id on the chain.
    pub fn machine_id(&self) -> u64 {
        poe_identity::device_id(&self.public_key())
    }

    /// Sign a message (a heartbeat, an act) with the device key.
    pub fn sign(&self, message: Vec<u8>) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        self.inner.lock().expect("device key lock").sign(&mut rng, &message)
    }
}

/// Verify a device signature against a public key — the check every
/// other participant runs on this device's signed acts.
#[uniffi::export]
pub fn verify_signature(public_key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
    dsa_verify(&public_key, &message, &signature)
}

/// The machine id a public key maps to, without holding the key.
#[uniffi::export]
pub fn machine_id_for_public_key(public_key: Vec<u8>) -> u64 {
    poe_identity::device_id(&public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_key_roundtrip_signs_and_restores() {
        let key = DeviceKey::generate();
        let pk = key.public_key();
        assert_eq!(key.machine_id(), poe_identity::device_id(&pk));
        assert_eq!(machine_id_for_public_key(pk.clone()), key.machine_id());

        let msg = b"epoch 12 heartbeat".to_vec();
        let sig = key.sign(msg.clone());
        assert!(verify_signature(pk.clone(), msg.clone(), sig.clone()));
        assert!(!verify_signature(pk.clone(), b"different".to_vec(), sig));

        // Export + restore yields the same identity.
        let restored = DeviceKey::from_bytes(pk.clone(), key.secret_key()).expect("restore");
        assert_eq!(restored.public_key(), pk);
        assert_eq!(restored.machine_id(), key.machine_id());

        // Garbage bytes are refused, not panicked on.
        assert!(DeviceKey::from_bytes(vec![1, 2, 3], vec![4, 5, 6]).is_err());
    }
}
