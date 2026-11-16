//! poe-vault — key custody behind one interface (PoE OS flag 1,
//! adopted 2026-11-15; Phase 0 item 2 of the device build scope).
//!
//! The suite's rule is that a device's signing keys live behind a
//! **secure-element interface**: callers ask the vault to sign, and
//! never handle secret key material themselves. In app-mode the
//! backend is the device's own vault (StrongBox / Secure Enclave /
//! TPM / OS keyring); on a standalone rig it is an ATECC608-class
//! chip; in development it is the file backend in this crate.
//!
//! This crate defines the interface ([`KeyVault`]) over the three
//! protocol key families a node holds:
//!
//! * the **device key** (ML-DSA-87) — the machine's identity; its
//!   public key hashes to the machine id;
//! * the **XMSS key** — stateful one-time vote signatures. The
//!   vault owns the state discipline: a leaf index is persisted
//!   *before* the signature it belongs to is released, exactly as
//!   `XmssKey::sign_persistent` has always done — through this
//!   interface there is no other way to sign;
//! * the **ticket chain** — the reveal chain whose commitment is
//!   registered at join; reveals are deterministic reads.
//!
//! Two backends are implemented. [`FileVault`] is the **software
//! stub**: it stores the keys in the node's data directory in the
//! exact formats the node has always used (`device.key` as two
//! hex lines, `ticket.seed` as 32 raw bytes, `xmss.key` in the
//! `POEXMSS1` state format), so existing node directories — and
//! their machine identities — carry over unchanged.
//! [`KeyringVault`] (feature `os-keyring`, Phase 1) stores the
//! same three secrets in the desktop's own key store — the
//! freedesktop Secret Service (GNOME Keyring / KWallet) — so the
//! material is encrypted at rest under the user's login instead
//! of sitting as plaintext files. Both are development/testnet
//! custody: [`KeyVault::mainnet_eligible`] returns `false` for
//! each, and a mainnet-profile build must refuse to run on a
//! backend that is not eligible. The honest limit, stated here
//! rather than discovered later: no commodity OS store performs
//! ML-DSA or XMSS signing internally, so with either backend the
//! key material enters process memory at sign time; the keyring
//! improves custody *at rest*, it is not hardware custody.
//! Hardware backends (an ATECC608-class chip on a standalone rig,
//! StrongBox-class stores) implement the same trait in later
//! phases without callers changing.
//!
//! Scope note, stated plainly: the libp2p **peer transport key**
//! (`peer.key`) is *not* behind this interface yet. It is a
//! transport credential, not an identity or value-signing key —
//! the machine's identity is the device key above — and libp2p's
//! keypair type has no remote-signing seam in the form this node
//! uses it. It stays in poe-net's custody until an OS-vault
//! backend gives it a proper home; nothing in this crate claims
//! otherwise.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use poe_crypto::hash::H512;
use poe_crypto::pq::DsaKeypair;
use poe_crypto::tickets::TicketChain;
use poe_crypto::xmss::{H32, XmssError, XmssKey, XmssSignature};
use poe_identity::device_id;
use rand::rngs::ThreadRng;
use rand::RngCore;

#[cfg(feature = "os-keyring")]
pub mod keyring;
#[cfg(feature = "os-keyring")]
pub use keyring::{KeyringVault, ThreadedKeyringVault};

/// Everything that can go wrong between a caller and its keys.
#[derive(Debug)]
pub enum VaultError {
    Io(io::Error),
    /// The stored device key does not parse or does not match its
    /// public half.
    BadDeviceKey,
    Xmss(XmssError),
    /// A platform key store (OS keyring) is unavailable, locked, or
    /// refused an operation. Backends never fall back silently on
    /// this error — custody downgrades are an operator's explicit
    /// choice, never a library's.
    Store(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::Io(e) => write!(f, "vault io: {e}"),
            VaultError::BadDeviceKey => write!(f, "stored device key does not parse"),
            VaultError::Xmss(e) => write!(f, "vault xmss: {e:?}"),
            VaultError::Store(msg) => write!(f, "vault key store: {msg}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<io::Error> for VaultError {
    fn from(e: io::Error) -> Self {
        VaultError::Io(e)
    }
}

impl From<XmssError> for VaultError {
    fn from(e: XmssError) -> Self {
        VaultError::Xmss(e)
    }
}

/// The key-custody interface. Signing methods take `&mut self`:
/// custody is a single-writer discipline (the XMSS state above
/// all), and no backend is asked to be safe under concurrent
/// signing.
pub trait KeyVault {
    /// The machine id: `device_id` of the device public key.
    fn machine(&self) -> u64;
    /// The device (ML-DSA-87) public key bytes — the identity other
    /// machines register and verify against.
    fn device_public_key(&self) -> Vec<u8>;
    /// Sign with the device key (ML-DSA-87, hedged).
    fn sign_device(&mut self, msg: &[u8]) -> Vec<u8>;
    /// The XMSS tree root — the vote-signing commitment registered
    /// at join.
    fn xmss_root(&self) -> H32;
    /// The next XMSS leaf index that will be used. Monotonic.
    fn xmss_next_index(&self) -> u64;
    /// Sign with the next XMSS one-time leaf. The advanced state is
    /// persisted before the signature is returned; a crash can burn
    /// a leaf, never reuse one.
    fn sign_xmss(&mut self, msg: &[u8]) -> Result<XmssSignature, VaultError>;
    /// The ticket chain's commitment (its tip).
    fn chain_commitment(&self) -> H512;
    /// The chain link to reveal at `step` (1-based).
    fn chain_reveal(&self, step: usize) -> H512;
    /// The backend's name, for logs and diagnostics.
    fn backend_name(&self) -> &'static str;
    /// Whether this backend may hold keys for a mainnet-profile
    /// node. Software stubs are never eligible.
    fn mainnet_eligible(&self) -> bool;
}

// -- the file backend (software stub) ----------------------------------------

/// The software-stub backend: the node's three protocol keys as
/// files in the node directory, in the formats the node has used
/// since the testnet launched. Dev and testnet only.
pub struct FileVault {
    device: DsaKeypair,
    machine: u64,
    chain: TicketChain,
    xmss: XmssKey,
    xmss_path: PathBuf,
    rng: ThreadRng,
}

impl FileVault {
    /// Load the keys from `dir`, creating any that are missing —
    /// the exact behaviour (and file formats) the node's own
    /// loader had before this crate existed. `chain_len` and
    /// `xmss_height` are the chain's parameters, used only when a
    /// fresh ticket seed or XMSS key must be generated; they are
    /// parameters, not constants, because they belong to the
    /// chain spec, not to key custody.
    pub fn load_or_create(
        dir: &Path,
        rng: &mut ThreadRng,
        chain_len: usize,
        xmss_height: u32,
    ) -> Result<FileVault, VaultError> {
        std::fs::create_dir_all(dir)?;
        let dev_path = dir.join("device.key");
        let device = if dev_path.exists() {
            let text = std::fs::read_to_string(&dev_path)?;
            let mut lines = text.lines();
            let pk = hex_decode(lines.next().unwrap_or("")).ok_or(VaultError::BadDeviceKey)?;
            let sk = hex_decode(lines.next().unwrap_or("")).ok_or(VaultError::BadDeviceKey)?;
            DsaKeypair::from_key_bytes(&pk, &sk).ok_or(VaultError::BadDeviceKey)?
        } else {
            let kp = DsaKeypair::generate(rng);
            std::fs::write(
                &dev_path,
                format!(
                    "{}\n{}\n",
                    hex_encode(&kp.public_key_bytes()),
                    hex_encode(&kp.secret_key_bytes())
                ),
            )?;
            kp
        };
        let machine = device_id(&device.public_key_bytes());

        let chain_path = dir.join("ticket.seed");
        let chain = if chain_path.exists() {
            let seed = std::fs::read(&chain_path)?;
            TicketChain::new(&seed, chain_len)
        } else {
            let mut seed = vec![0u8; 32];
            rng.fill_bytes(&mut seed);
            std::fs::write(&chain_path, &seed)?;
            TicketChain::new(&seed, chain_len)
        };

        let xmss_path = dir.join("xmss.key");
        let xmss = if xmss_path.exists() {
            XmssKey::load(&xmss_path)?
        } else {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let key = XmssKey::generate(seed, xmss_height);
            key.save(&xmss_path)?;
            key
        };
        Ok(FileVault { device, machine, chain, xmss, xmss_path, rng: rand::thread_rng() })
    }
}

impl KeyVault for FileVault {
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
        Ok(self.xmss.sign_persistent(&self.xmss_path, msg)?)
    }

    fn chain_commitment(&self) -> H512 {
        self.chain.commitment()
    }

    fn chain_reveal(&self, step: usize) -> H512 {
        self.chain.reveal(step)
    }

    fn backend_name(&self) -> &'static str {
        "file (software stub)"
    }

    fn mainnet_eligible(&self) -> bool {
        false
    }
}

// -- hex (the device.key file format) -----------------------------------------

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub(crate) fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use poe_crypto::pq::dsa_verify;
    use poe_crypto::tickets::verify_reveal;

    const TEST_CHAIN_LEN: usize = 128;
    // Height 6 (64 leaves), not the testnet's 15: in a debug build
    // each leaf's WOTS+ hash chain is expensive, and the custody
    // semantics these tests pin (persistence, reload, no reuse)
    // are height-independent.
    const TEST_XMSS_HEIGHT: u32 = 6;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("poe-vault-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn open(dir: &Path) -> FileVault {
        let mut rng = rand::thread_rng();
        FileVault::load_or_create(dir, &mut rng, TEST_CHAIN_LEN, TEST_XMSS_HEIGHT).unwrap()
    }

    #[test]
    fn create_then_reload_keeps_the_identity() {
        let dir = temp_dir("identity");
        let v1 = open(&dir);
        let (m, pk, root, commitment) =
            (v1.machine(), v1.device_public_key(), v1.xmss_root(), v1.chain_commitment());
        assert!(dir.join("device.key").exists());
        assert!(dir.join("ticket.seed").exists());
        assert!(dir.join("xmss.key").exists());
        drop(v1);
        let v2 = open(&dir);
        assert_eq!(v2.machine(), m, "machine id must survive a reload");
        assert_eq!(v2.device_public_key(), pk);
        assert_eq!(v2.xmss_root(), root);
        assert_eq!(v2.chain_commitment(), commitment);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn device_signatures_verify_against_the_public_key() {
        let dir = temp_dir("dsa");
        let mut v = open(&dir);
        let sig = v.sign_device(b"heartbeat");
        assert!(dsa_verify(&v.device_public_key(), b"heartbeat", &sig));
        assert!(!dsa_verify(&v.device_public_key(), b"other", &sig));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn xmss_leaves_are_never_reused_across_a_reload() {
        let dir = temp_dir("xmss");
        let root;
        {
            let mut v = open(&dir);
            root = v.xmss_root();
            let s0 = v.sign_xmss(b"vote one").unwrap();
            assert_eq!(s0.leaf, 0);
            assert!(poe_crypto::xmss::verify(&root, TEST_XMSS_HEIGHT, b"vote one", &s0));
            assert_eq!(v.xmss_next_index(), 1);
        }
        // A fresh vault over the same directory resumes at leaf 1:
        // the first signature's leaf was persisted before release.
        let mut v = open(&dir);
        assert_eq!(v.xmss_next_index(), 1);
        let s1 = v.sign_xmss(b"vote two").unwrap();
        assert_eq!(s1.leaf, 1);
        assert!(poe_crypto::xmss::verify(&root, TEST_XMSS_HEIGHT, b"vote two", &s1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_reveals_verify_against_the_commitment() {
        let dir = temp_dir("chain");
        let v = open(&dir);
        let commitment = v.chain_commitment();
        for step in [1usize, 2, 40] {
            let link = v.chain_reveal(step);
            assert!(verify_reveal(&commitment, step, &link), "reveal at step {step} must verify");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_file_backend_is_a_stub_and_says_so() {
        let dir = temp_dir("stub");
        let v = open(&dir);
        assert!(!v.mainnet_eligible());
        assert_eq!(v.backend_name(), "file (software stub)");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
