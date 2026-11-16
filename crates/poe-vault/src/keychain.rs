//! The macOS Keychain backend (PoE OS Phase 1).
//!
//! Custody: the node's three protocol secrets are generic-
//! password items in the user's login Keychain, under the
//! service `app.poe.suite.vault` with accounts
//! `<vault-id>:<item>` — the macOS counterpart of the Secret
//! Service keyring backend on Linux and DPAPI on Windows.
//!
//! The honest limit is the same as the other OS stores: the
//! Keychain does not sign ML-DSA or XMSS internally (the
//! Secure Enclave holds only its own key types), so key
//! material enters process memory at sign time. What the
//! Keychain buys is custody at rest under the user's login.
//! `mainnet_eligible` is therefore false.
//!
//! Persist-before-release holds exactly as with the other
//! backends: the XMSS state item is replaced before any
//! signature leaves `sign_xmss` (through
//! `XmssKey::sign_persistent_with`).

use poe_crypto::hash::H512;
use poe_crypto::pq::DsaKeypair;
use poe_crypto::tickets::TicketChain;
use poe_crypto::xmss::{H32, XmssKey, XmssSignature};
use poe_identity::device_id;
use rand::rngs::ThreadRng;
use rand::RngCore;
use security_framework::passwords::{get_generic_password, set_generic_password};

use crate::{hex_decode, hex_encode, KeyVault, VaultError};

const SERVICE: &str = "app.poe.suite.vault";
/// errSecItemNotFound: the item does not exist (yet).
const ITEM_NOT_FOUND: i32 = -25300;

fn account(vault_id: &str, item: &str) -> String {
    format!("{vault_id}:{item}")
}

fn get(vault_id: &str, item: &str) -> Result<Option<Vec<u8>>, VaultError> {
    match get_generic_password(SERVICE, &account(vault_id, item)) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.code() == ITEM_NOT_FOUND => Ok(None),
        Err(e) => Err(VaultError::Store(format!("Keychain read of {item} failed: {e}"))),
    }
}

fn set(vault_id: &str, item: &str, bytes: &[u8]) -> Result<(), VaultError> {
    set_generic_password(SERVICE, &account(vault_id, item), bytes)
        .map_err(|e| VaultError::Store(format!("Keychain write of {item} failed: {e}")))
}

/// The Keychain backend. Selected with `POE_VAULT=keychain`
/// on macOS. A Keychain vault is a different identity from
/// the same directory's file keys — switching backends is an
/// operator migration, as with every backend.
pub struct KeychainVault {
    vault_id: String,
    device: DsaKeypair,
    machine: u64,
    chain: TicketChain,
    xmss: XmssKey,
    rng: ThreadRng,
}

impl KeychainVault {
    pub fn load_or_create(
        vault_id: &str,
        rng: &mut ThreadRng,
        chain_len: usize,
        xmss_height: u32,
    ) -> Result<KeychainVault, VaultError> {
        let device = match get(vault_id, "device-key")? {
            Some(plain) => {
                let text = String::from_utf8(plain).map_err(|_| VaultError::BadDeviceKey)?;
                let mut lines = text.lines();
                let pk = hex_decode(lines.next().unwrap_or("")).ok_or(VaultError::BadDeviceKey)?;
                let sk = hex_decode(lines.next().unwrap_or("")).ok_or(VaultError::BadDeviceKey)?;
                DsaKeypair::from_key_bytes(&pk, &sk).ok_or(VaultError::BadDeviceKey)?
            }
            None => {
                let kp = DsaKeypair::generate(rng);
                let text = format!(
                    "{}\n{}\n",
                    hex_encode(&kp.public_key_bytes()),
                    hex_encode(&kp.secret_key_bytes())
                );
                set(vault_id, "device-key", text.as_bytes())?;
                kp
            }
        };
        let machine = device_id(&device.public_key_bytes());

        let chain = match get(vault_id, "ticket-seed")? {
            Some(seed) => TicketChain::new(&seed, chain_len),
            None => {
                let mut seed = vec![0u8; 32];
                rng.fill_bytes(&mut seed);
                set(vault_id, "ticket-seed", &seed)?;
                TicketChain::new(&seed, chain_len)
            }
        };

        let xmss = match get(vault_id, "xmss-state")? {
            Some(state) => XmssKey::from_state_bytes(&state)?,
            None => {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                let key = XmssKey::generate(seed, xmss_height);
                set(vault_id, "xmss-state", &key.state_bytes())?;
                key
            }
        };
        Ok(KeychainVault {
            vault_id: vault_id.to_string(),
            device,
            machine,
            chain,
            xmss,
            rng: rand::thread_rng(),
        })
    }
}

impl KeyVault for KeychainVault {
    fn machine(&self) -> u64 {
        self.machine
    }

    fn device_public_key(&self) -> Vec<u8> {
        self.device.public_key_bytes()
    }

    fn sign_device(&mut self, msg: &[u8]) -> Vec<u8> {
        self.device.sign(&mut self.rng, msg)
    }

    fn xmss_root(&self) -> H32 {
        self.xmss.root()
    }

    fn xmss_next_index(&self) -> u64 {
        self.xmss.next_index()
    }

    fn sign_xmss(&mut self, msg: &[u8]) -> Result<XmssSignature, VaultError> {
        let vault_id = self.vault_id.clone();
        let mut persist = |bytes: &[u8]| -> Result<(), poe_crypto::xmss::XmssError> {
            set(&vault_id, "xmss-state", bytes).map_err(|e| {
                poe_crypto::xmss::XmssError::Io(std::io::Error::other(e.to_string()))
            })
        };
        Ok(self.xmss.sign_persistent_with(&mut persist, msg)?)
    }

    fn chain_commitment(&self) -> H512 {
        self.chain.commitment()
    }

    fn chain_reveal(&self, step: usize) -> H512 {
        self.chain.reveal(step)
    }

    fn backend_name(&self) -> &'static str {
        "macOS Keychain"
    }

    fn mainnet_eligible(&self) -> bool {
        false
    }
}
