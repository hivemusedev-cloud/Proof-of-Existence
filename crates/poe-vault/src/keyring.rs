//! The OS-keyring backend (PoE OS Phase 1): the node's three
//! protocol secrets held by the desktop's own key store through
//! the freedesktop **Secret Service** API (GNOME Keyring,
//! KWallet, and compatible services), instead of plaintext files
//! in the node directory.
//!
//! Custody shape, stated plainly (the crate docs carry the full
//! version): the store encrypts the secrets at rest under the
//! user's login keyring. It does not — and on today's desktops
//! cannot — perform ML-DSA or XMSS signing itself, so the vault
//! unseals the material into process memory to sign, exactly as
//! the file backend reads its files. This backend is therefore
//! `mainnet_eligible() == false` like the stub; what it removes
//! is plaintext-at-rest, not memory exposure. A locked or
//! unreachable keyring is a hard error ([`VaultError::Store`]):
//! the backend never falls back to files on its own.
//!
//! The three items live in the default collection under the
//! attributes `{application: "poe-vault", vault-id: <id>, item:
//! <name>}`: `device-key` (the same two hex lines the file
//! format uses), `ticket-seed` (32 raw bytes), and `xmss-state`
//! (the 84 `POEXMSS1` state bytes, replaced on every signature —
//! the store write completes before the signature is released,
//! through `XmssKey::sign_persistent_with`).

use std::collections::HashMap;
use std::sync::mpsc;

use poe_crypto::hash::H512;
use poe_crypto::pq::DsaKeypair;
use poe_crypto::tickets::TicketChain;
use poe_crypto::xmss::{H32, XmssKey, XmssSignature};
use poe_identity::device_id;
use rand::rngs::ThreadRng;
use rand::RngCore;
use secret_service::blocking::{Collection, SecretService};
use secret_service::EncryptionType;

use crate::{hex_decode, hex_encode, KeyVault, VaultError};

const APP: &str = "poe-vault";
const ITEM_DEVICE: &str = "device-key";
const ITEM_SEED: &str = "ticket-seed";
const ITEM_XMSS: &str = "xmss-state";
const CONTENT_TYPE: &str = "application/octet-stream";

fn store_err(e: secret_service::Error) -> VaultError {
    VaultError::Store(e.to_string())
}

/// A [`KeyVault`] whose secrets live in the OS keyring. One
/// instance owns one Secret Service session; custody is
/// single-writer, as the trait requires.
pub struct KeyringVault {
    service: SecretService<'static>,
    vault_id: String,
    device: DsaKeypair,
    machine: u64,
    chain: TicketChain,
    xmss: XmssKey,
    rng: ThreadRng,
}

impl KeyringVault {
    /// Load the vault named `vault_id` from the OS keyring,
    /// creating (and storing) any secret that is missing — the
    /// keyring analogue of [`crate::FileVault::load_or_create`].
    /// `chain_len` and `xmss_height` are the chain's parameters,
    /// used only for fresh generation. Fails with
    /// [`VaultError::Store`] if no Secret Service is reachable or
    /// the default collection cannot be unlocked.
    pub fn load_or_create(
        vault_id: &str,
        rng: &mut ThreadRng,
        chain_len: usize,
        xmss_height: u32,
    ) -> Result<KeyringVault, VaultError> {
        let service = SecretService::connect(EncryptionType::Dh).map_err(store_err)?;
        service.get_default_collection().map_err(store_err)?.ensure_unlocked().map_err(|e| {
            VaultError::Store(format!(
                "default keyring collection is locked or unavailable: {e}"
            ))
        })?;
        let mut vault = KeyringVault {
            service,
            vault_id: vault_id.to_string(),
            device: DsaKeypair::generate(rng), // placeholder, replaced below
            machine: 0,
            chain: TicketChain::new(&[0u8; 32], chain_len),
            xmss: XmssKey::generate([0u8; 32], 1),
            rng: rand::thread_rng(),
        };

        // Device key: stored as the file format's two hex lines.
        let device = match vault.get(ITEM_DEVICE)? {
            Some(bytes) => {
                let text = String::from_utf8(bytes).map_err(|_| VaultError::BadDeviceKey)?;
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
                vault.put(ITEM_DEVICE, text.as_bytes())?;
                kp
            }
        };
        vault.machine = device_id(&device.public_key_bytes());
        vault.device = device;

        // Ticket chain: 32 raw seed bytes.
        let seed = match vault.get(ITEM_SEED)? {
            Some(bytes) => bytes,
            None => {
                let mut seed = vec![0u8; 32];
                rng.fill_bytes(&mut seed);
                vault.put(ITEM_SEED, &seed)?;
                seed
            }
        };
        vault.chain = TicketChain::new(&seed, chain_len);

        // XMSS key: the canonical state bytes.
        vault.xmss = match vault.get(ITEM_XMSS)? {
            Some(bytes) => XmssKey::from_state_bytes(&bytes)?,
            None => {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                let key = XmssKey::generate(seed, xmss_height);
                vault.put(ITEM_XMSS, &key.state_bytes())?;
                key
            }
        };
        Ok(vault)
    }

    fn attributes<'a>(&'a self, item: &'a str) -> HashMap<&'a str, &'a str> {
        HashMap::from([
            ("application", APP),
            ("vault-id", self.vault_id.as_str()),
            ("item", item),
        ])
    }

    /// The default collection, fetched per operation: the
    /// blocking `Collection` borrows the service, so it cannot be
    /// stored beside it in one struct. The fetch is one D-Bus
    /// property read — negligible next to a signature.
    fn collection(&self) -> Result<Collection<'_>, VaultError> {
        self.service.get_default_collection().map_err(store_err)
    }

    fn get(&self, item: &str) -> Result<Option<Vec<u8>>, VaultError> {
        let collection = self.collection()?;
        let found = collection.search_items(self.attributes(item)).map_err(store_err)?;
        match found.first() {
            Some(stored) => Ok(Some(stored.get_secret().map_err(store_err)?)),
            None => Ok(None),
        }
    }

    fn put(&self, item: &str, secret: &[u8]) -> Result<(), VaultError> {
        self.collection()?
            .create_item(
                &format!("PoE vault {} {item}", self.vault_id),
                self.attributes(item),
                secret,
                true, // replace any existing item with these attributes
                CONTENT_TYPE,
            )
            .map_err(store_err)?;
        Ok(())
    }

    /// Delete this vault's three items from the keyring (used by
    /// tests and by an operator retiring a keyring-held identity;
    /// the node itself never calls it).
    pub fn delete_all(&self) -> Result<(), VaultError> {
        for item in [ITEM_DEVICE, ITEM_SEED, ITEM_XMSS] {
            let collection = self.collection()?;
            let found = collection.search_items(self.attributes(item)).map_err(store_err)?;
            for stored in found {
                stored.delete().map_err(store_err)?;
            }
        }
        Ok(())
    }
}

impl KeyVault for KeyringVault {
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
        // Persist-before-release, with the keyring store as the
        // persistence: the state item is replaced (and the store
        // has acknowledged) before the signature exists. The
        // fields are destructured so the collection (borrowed
        // from the service) and the XMSS key (mutated by signing)
        // are independent borrows.
        let Self { service, vault_id, xmss, .. } = self;
        let collection = service.get_default_collection().map_err(store_err)?;
        let attributes: HashMap<String, String> = HashMap::from([
            ("application".to_string(), APP.to_string()),
            ("vault-id".to_string(), vault_id.clone()),
            ("item".to_string(), ITEM_XMSS.to_string()),
        ]);
        let label = format!("PoE vault {} {ITEM_XMSS}", vault_id);
        let mut persist = |bytes: &[u8]| -> Result<(), poe_crypto::xmss::XmssError> {
            let attrs: HashMap<&str, &str> =
                attributes.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            collection
                .create_item(&label, attrs, bytes, true, CONTENT_TYPE)
                .map_err(|e| {
                    poe_crypto::xmss::XmssError::Io(std::io::Error::other(e.to_string()))
                })?;
            Ok(())
        };
        Ok(xmss.sign_persistent_with(&mut persist, msg)?)
    }

    fn chain_commitment(&self) -> poe_crypto::hash::H512 {
        self.chain.commitment()
    }

    fn chain_reveal(&self, step: usize) -> poe_crypto::hash::H512 {
        self.chain.reveal(step)
    }

    fn backend_name(&self) -> &'static str {
        "OS keyring (Secret Service)"
    }

    fn mainnet_eligible(&self) -> bool {
        false
    }
}

// -- the threaded front-end ---------------------------------------------------
//
// The Secret Service client is a *blocking* D-Bus client whose
// transport starts its own runtime; calling it from a thread
// that is itself driving an async runtime panics ("Cannot start
// a runtime from within a runtime" — observed live: poe-node
// runs its node inside a tokio runtime, and the direct backend
// crashed it at startup). [`ThreadedKeyringVault`] is the form
// async hosts use: a dedicated OS thread owns a [`KeyringVault`]
// (and its D-Bus session), and every trait call is a channel
// round-trip to that thread. The arrangement also makes the
// trait's single-writer custody structural: the owning thread
// is the only writer there can be.

enum Cmd {
    SignDevice(Vec<u8>, mpsc::Sender<Vec<u8>>),
    XmssNextIndex(mpsc::Sender<u64>),
    SignXmss(Vec<u8>, mpsc::Sender<Result<XmssSignature, VaultError>>),
    ChainReveal(usize, mpsc::Sender<H512>),
}

/// A [`KeyVault`] front-end that keeps the real keyring vault on
/// its own thread — see the module note above. The immutable
/// identity facts (machine, public key, XMSS root, chain
/// commitment) are fetched once at construction and answered
/// locally; everything stateful goes to the owning thread.
pub struct ThreadedKeyringVault {
    tx: mpsc::Sender<Cmd>,
    machine: u64,
    device_public_key: Vec<u8>,
    xmss_root: H32,
    chain_commitment: H512,
}

impl ThreadedKeyringVault {
    /// Spawn the owning thread and load (or create) the named
    /// vault there. A keyring failure on that thread is returned
    /// here as the same [`VaultError::Store`] the direct backend
    /// would produce — still no fallback, still fatal to the
    /// caller that asked for keyring custody.
    pub fn load_or_create(
        vault_id: &str,
        chain_len: usize,
        xmss_height: u32,
    ) -> Result<ThreadedKeyringVault, VaultError> {
        let (tx, rx) = mpsc::channel::<Cmd>();
        let (ready_tx, ready_rx) =
            mpsc::channel::<Result<(u64, Vec<u8>, H32, H512), VaultError>>();
        let vault_id = vault_id.to_string();
        std::thread::Builder::new()
            .name("poe-vault-keyring".to_string())
            .spawn(move || {
                let mut rng = rand::thread_rng();
                let mut vault =
                    match KeyringVault::load_or_create(&vault_id, &mut rng, chain_len, xmss_height) {
                        Ok(v) => v,
                        Err(e) => {
                            let _ = ready_tx.send(Err(e));
                            return;
                        }
                    };
                let identity = (
                    vault.machine(),
                    vault.device_public_key(),
                    vault.xmss_root(),
                    vault.chain_commitment(),
                );
                if ready_tx.send(Ok(identity)).is_err() {
                    return;
                }
                for cmd in rx {
                    match cmd {
                        Cmd::SignDevice(msg, reply) => {
                            let _ = reply.send(vault.sign_device(&msg));
                        }
                        Cmd::XmssNextIndex(reply) => {
                            let _ = reply.send(vault.xmss_next_index());
                        }
                        Cmd::SignXmss(msg, reply) => {
                            let _ = reply.send(vault.sign_xmss(&msg));
                        }
                        Cmd::ChainReveal(step, reply) => {
                            let _ = reply.send(vault.chain_reveal(step));
                        }
                    }
                }
            })
            .map_err(VaultError::Io)?;
        let (machine, device_public_key, xmss_root, chain_commitment) = ready_rx
            .recv()
            .map_err(|_| VaultError::Store("keyring vault thread died during load".into()))??;
        Ok(ThreadedKeyringVault { tx, machine, device_public_key, xmss_root, chain_commitment })
    }

    fn roundtrip<T>(&self, cmd: impl FnOnce(mpsc::Sender<T>) -> Cmd) -> T {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx
            .send(cmd(reply_tx))
            .expect("keyring vault thread is gone");
        reply_rx.recv().expect("keyring vault thread is gone")
    }
}

impl KeyVault for ThreadedKeyringVault {
    fn machine(&self) -> u64 {
        self.machine
    }

    fn device_public_key(&self) -> Vec<u8> {
        self.device_public_key.clone()
    }

    fn sign_device(&mut self, msg: &[u8]) -> Vec<u8> {
        self.roundtrip(|reply| Cmd::SignDevice(msg.to_vec(), reply))
    }

    fn xmss_root(&self) -> H32 {
        self.xmss_root
    }

    fn xmss_next_index(&self) -> u64 {
        self.roundtrip(Cmd::XmssNextIndex)
    }

    fn sign_xmss(&mut self, msg: &[u8]) -> Result<XmssSignature, VaultError> {
        self.roundtrip(|reply| Cmd::SignXmss(msg.to_vec(), reply))
    }

    fn chain_commitment(&self) -> H512 {
        self.chain_commitment
    }

    fn chain_reveal(&self, step: usize) -> H512 {
        self.roundtrip(|reply| Cmd::ChainReveal(step, reply))
    }

    fn backend_name(&self) -> &'static str {
        "OS keyring (Secret Service)"
    }

    fn mainnet_eligible(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use poe_crypto::pq::dsa_verify;
    use poe_crypto::tickets::verify_reveal;

    const TEST_CHAIN_LEN: usize = 128;
    const TEST_XMSS_HEIGHT: u32 = 6; // as in the file-backend tests

    fn open(id: &str) -> KeyringVault {
        let mut rng = rand::thread_rng();
        KeyringVault::load_or_create(id, &mut rng, TEST_CHAIN_LEN, TEST_XMSS_HEIGHT).unwrap()
    }

    /// The whole keyring battery in one test function: the tests
    /// share the process environment (the session-bus address), so
    /// they run sequentially here rather than as parallel tests.
    /// Skipped unless POE_TEST_KEYRING=1 — a keyring is a desktop
    /// service, not something every build machine has. On this
    /// machine the service is the home-installed GNOME Keyring
    /// (~/tools/keyring/start-keyring.sh).
    #[test]
    fn keyring_battery() {
        // An unreachable bus must be a clean Store error, never a
        // panic and never a silent fallback to files.
        let saved = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok();
        std::env::set_var("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/poe-test-bus");
        let mut rng = rand::thread_rng();
        let refused = KeyringVault::load_or_create(
            "poe-test-unreachable",
            &mut rng,
            TEST_CHAIN_LEN,
            TEST_XMSS_HEIGHT,
        );
        match saved {
            Some(addr) => std::env::set_var("DBUS_SESSION_BUS_ADDRESS", addr),
            None => std::env::remove_var("DBUS_SESSION_BUS_ADDRESS"),
        }
        assert!(
            matches!(refused, Err(VaultError::Store(_))),
            "an unreachable keyring must refuse with a Store error, got: {:?}",
            refused.map(|_| ())
        );

        if std::env::var("POE_TEST_KEYRING").as_deref() != Ok("1") {
            eprintln!("POE_TEST_KEYRING != 1 — live keyring battery skipped");
            return;
        }

        let id = format!("poe-test-{}", std::process::id());
        // Create, then check the custody battery against a RELOAD
        // (a fresh Secret Service session over the same items).
        let (m, pk, root, commitment) = {
            let v = open(&id);
            (v.machine(), v.device_public_key(), v.xmss_root(), v.chain_commitment())
        };
        let mut v = open(&id);
        assert_eq!(v.machine(), m, "machine id must survive a keyring reload");
        assert_eq!(v.device_public_key(), pk);
        assert_eq!(v.xmss_root(), root);
        assert_eq!(v.chain_commitment(), commitment);
        assert!(!v.mainnet_eligible());
        assert_eq!(v.backend_name(), "OS keyring (Secret Service)");

        let sig = v.sign_device(b"heartbeat");
        assert!(dsa_verify(&v.device_public_key(), b"heartbeat", &sig));

        let commitment = v.chain_commitment();
        for step in [1usize, 2, 40] {
            assert!(verify_reveal(&commitment, step, &v.chain_reveal(step)));
        }

        // XMSS leaves never reused across a reload: sign once,
        // drop, reconnect — the next leaf must have advanced,
        // because the state write reached the keyring before the
        // first signature was released.
        let s0 = v.sign_xmss(b"vote one").unwrap();
        assert_eq!(s0.leaf, 0);
        assert!(poe_crypto::xmss::verify(&root, TEST_XMSS_HEIGHT, b"vote one", &s0));
        drop(v);
        let mut v = open(&id);
        assert_eq!(v.xmss_next_index(), 1);
        let s1 = v.sign_xmss(b"vote two").unwrap();
        assert_eq!(s1.leaf, 1);
        assert!(poe_crypto::xmss::verify(&root, TEST_XMSS_HEIGHT, b"vote two", &s1));

        v.delete_all().unwrap();
        // After deletion a fresh open mints a NEW identity (the
        // items are gone, so load_or_create regenerates them).
        let v2 = open(&id);
        assert_ne!(v2.machine(), m);
        v2.delete_all().unwrap();

        // Regression: the threaded front-end must work from
        // inside a tokio runtime — the direct backend panics
        // there ("Cannot start a runtime from within a runtime",
        // zbus), which is how poe-node found it. This is the
        // node's exact arrangement: vault calls made on a
        // runtime thread, custody on the vault's own thread.
        let tid = format!("poe-test-threaded-{}", std::process::id());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (tm, troot) = rt.block_on(async {
            let mut tv =
                ThreadedKeyringVault::load_or_create(&tid, TEST_CHAIN_LEN, TEST_XMSS_HEIGHT)
                    .unwrap();
            assert_eq!(tv.backend_name(), "OS keyring (Secret Service)");
            assert!(!tv.mainnet_eligible());
            let sig = tv.sign_device(b"heartbeat");
            assert!(dsa_verify(&tv.device_public_key(), b"heartbeat", &sig));
            let root = tv.xmss_root();
            let s0 = tv.sign_xmss(b"vote one").unwrap();
            assert_eq!(s0.leaf, 0);
            assert!(poe_crypto::xmss::verify(&root, TEST_XMSS_HEIGHT, b"vote one", &s0));
            (tv.machine(), root)
        });
        // A second threaded instance over the same items resumes
        // at leaf 1 — persist-before-release held across the
        // channel and the process's D-Bus sessions.
        rt.block_on(async {
            let mut tv =
                ThreadedKeyringVault::load_or_create(&tid, TEST_CHAIN_LEN, TEST_XMSS_HEIGHT)
                    .unwrap();
            assert_eq!(tv.machine(), tm);
            assert_eq!(tv.xmss_root(), troot);
            assert_eq!(tv.xmss_next_index(), 1);
        });
        open(&tid).delete_all().unwrap();
    }
}
