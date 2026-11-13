//! XMSS-style one-time vote keys.
//!
//! Committee votes are signed with one-time keys: each leaf of a Merkle
//! tree is a WOTS+ keypair (Winternitz chains over `H`, w = 16) that may
//! sign exactly once. Reusing a leaf is the one unforgivable error — two
//! signatures from one leaf leak the chain middles and let others forge —
//! so this module makes reuse impossible by construction:
//!
//! * an index is handed out only by `reserve`/`sign_persistent`, which
//!   **persist the advanced state to disk (write + fsync + atomic rename)
//!   before any signature is produced**;
//! * a crash after the persist but before the release burns the leaf —
//!   the reloaded key resumes at the next index, never at the burned one;
//! * exhaust the tree and signing stops with [`XmssError::Exhausted`].
//!
//! Scope, stated plainly: this is the single-tree member of the XMSS
//! family (the manual's carrier is a 2^40-leaf multi-tree; the hypertree
//! layering and the production audit belong to the Step 5 hardening pass).
//! What is carried here in full is the part the finality layer depends on:
//! the state discipline.

use crate::hash::{h, Part};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// A 256-bit hash value (the first half of an `H` output).
pub type H32 = [u8; 32];

fn h32(tag: &str, parts: &[Part]) -> H32 {
    let d = h(tag, parts);
    d[..32].try_into().expect("64-byte digest")
}

const W: u32 = 16; // Winternitz parameter: base-16 digits
const LEN1: usize = 64; // digits of a 256-bit digest, 2 per byte
const LEN2: usize = 3; // checksum digits (max sum 64*15 = 960 < 16^3)
const LEN: usize = LEN1 + LEN2;

#[derive(Debug)]
pub enum XmssError {
    /// Every leaf has been used or burned. The key is finished, forever.
    Exhausted,
    Io(io::Error),
    /// The state file is malformed or its root does not match its seed.
    BadState,
}

impl From<io::Error> for XmssError {
    fn from(e: io::Error) -> Self {
        XmssError::Io(e)
    }
}

fn digits_of(msg: &[u8]) -> [u8; LEN] {
    let digest = h32("msg", &[Part::Bytes(msg)]);
    let mut digits = [0u8; LEN];
    for (i, byte) in digest.iter().enumerate() {
        digits[2 * i] = byte >> 4;
        digits[2 * i + 1] = byte & 0x0f;
    }
    let checksum: u32 = digits[..LEN1].iter().map(|&d| (W - 1) - (d as u32)).sum();
    digits[LEN1] = ((checksum >> 8) & 0x0f) as u8;
    digits[LEN1 + 1] = ((checksum >> 4) & 0x0f) as u8;
    digits[LEN1 + 2] = (checksum & 0x0f) as u8;
    digits
}

fn chain(mut x: H32, chain_idx: usize, steps: u32, from_step: u32) -> H32 {
    for s in 0..steps {
        x = h32(
            "wots-chain",
            &[
                Part::Bytes(&x),
                Part::Nat(chain_idx as u64),
                Part::Nat((from_step + s) as u64),
            ],
        );
    }
    x
}

fn chain_start(seed: &[u8; 32], leaf: u64, chain_idx: usize) -> H32 {
    h32(
        "wots-sk",
        &[Part::Bytes(seed), Part::Nat(leaf), Part::Nat(chain_idx as u64)],
    )
}

fn leaf_hash(seed: &[u8; 32], leaf: u64) -> H32 {
    let mut concat = Vec::with_capacity(LEN * 32);
    for i in 0..LEN {
        let start = chain_start(seed, leaf, i);
        concat.extend_from_slice(&chain(start, i, W - 1, 0));
    }
    h32("leaf", &[Part::Bytes(&concat)])
}

fn build_levels(leaf_hashes: Vec<H32>) -> Vec<Vec<H32>> {
    let mut levels = vec![leaf_hashes];
    while levels.last().expect("levels").len() > 1 {
        let cur = levels.last().expect("levels").clone();
        let mut next = Vec::with_capacity(cur.len() / 2);
        for pair in cur.chunks_exact(2) {
            next.push(h32("node", &[Part::Bytes(&pair[0]), Part::Bytes(&pair[1])]));
        }
        levels.push(next);
    }
    levels
}

/// An XMSS keypair and its one-time-leaf state.
pub struct XmssKey {
    seed: [u8; 32],
    height: u32,
    next: u64,
    levels: Vec<Vec<H32>>,
}

/// A signature: the leaf that signed, the WOTS+ chain values, and the
/// leaf's authentication path to the tree root.
#[derive(Clone)]
pub struct XmssSignature {
    pub leaf: u64,
    pub wots: Vec<H32>,
    pub auth: Vec<H32>,
}

impl XmssKey {
    /// Generate a key with `2^height` one-time leaves from a 32-byte seed.
    pub fn generate(seed: [u8; 32], height: u32) -> XmssKey {
        assert!((1..=20).contains(&height), "height out of supported range");
        let leaves = 1usize << height;
        let leaf_hashes: Vec<H32> = (0..leaves as u64).map(|l| leaf_hash(&seed, l)).collect();
        XmssKey {
            seed,
            height,
            next: 0,
            levels: build_levels(leaf_hashes),
        }
    }

    /// The public commitment: the Merkle root over all one-time leaves.
    pub fn root(&self) -> H32 {
        *self.levels.last().expect("levels")[0..1].first().expect("root")
    }

    /// The next leaf index that will be used. Monotonic, forever.
    pub fn next_index(&self) -> u64 {
        self.next
    }

    fn capacity(&self) -> u64 {
        1u64 << self.height
    }

    fn sign_at(&self, leaf: u64, msg: &[u8]) -> XmssSignature {
        let digits = digits_of(msg);
        let mut wots = Vec::with_capacity(LEN);
        for i in 0..LEN {
            let start = chain_start(&self.seed, leaf, i);
            wots.push(chain(start, i, digits[i] as u32, 0));
        }
        let mut auth = Vec::with_capacity(self.height as usize);
        let mut idx = leaf as usize;
        for level in &self.levels[..self.levels.len() - 1] {
            auth.push(level[idx ^ 1]);
            idx /= 2;
        }
        XmssSignature { leaf, wots, auth }
    }

    /// Sign in memory only (tests, simulation). Production signing goes
    /// through [`XmssKey::sign_persistent`], which persists state first.
    pub fn sign(&mut self, msg: &[u8]) -> Result<XmssSignature, XmssError> {
        if self.next >= self.capacity() {
            return Err(XmssError::Exhausted);
        }
        let leaf = self.next;
        self.next += 1;
        Ok(self.sign_at(leaf, msg))
    }

    /// Reserve (and burn) the next leaf index, persisting the advanced
    /// state first. Returns the reserved index. This is the exact point a
    /// crash turns a leaf into a burned leaf instead of a reused one.
    pub fn reserve(&mut self, path: &Path) -> Result<u64, XmssError> {
        if self.next >= self.capacity() {
            return Err(XmssError::Exhausted);
        }
        let leaf = self.next;
        self.next += 1;
        self.save(path)?;
        Ok(leaf)
    }

    /// Sign with the state discipline: advance + persist, then sign.
    pub fn sign_persistent(&mut self, path: &Path, msg: &[u8]) -> Result<XmssSignature, XmssError> {
        let leaf = self.reserve(path)?;
        Ok(self.sign_at(leaf, msg))
    }

    // -- state file ---------------------------------------------------------
    // Layout: magic "POEXMSS1" | height u32 BE | next u64 BE | seed | root.

    /// Persist the state atomically: write a temp file, fsync it, rename
    /// over the old state. A crash mid-save leaves either the old or the
    /// new state, never a torn one — and since the index only ever moves
    /// forward before a signature exists, both are safe.
    pub fn save(&self, path: &Path) -> Result<(), XmssError> {
        let mut buf = Vec::with_capacity(84);
        buf.extend_from_slice(b"POEXMSS1");
        buf.extend_from_slice(&self.height.to_be_bytes());
        buf.extend_from_slice(&self.next.to_be_bytes());
        buf.extend_from_slice(&self.seed);
        buf.extend_from_slice(&self.root());
        let mut tmp: PathBuf = path.to_path_buf();
        tmp.set_extension("tmp");
        fs::write(&tmp, &buf)?;
        fs::File::open(&tmp)?.sync_all()?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Load a key from its state file. The stored root is recomputed from
    /// the seed and checked — a state that does not match its root is
    /// refused, not trusted.
    pub fn load(path: &Path) -> Result<XmssKey, XmssError> {
        let buf = fs::read(path)?;
        if buf.len() != 84 || &buf[..8] != b"POEXMSS1" {
            return Err(XmssError::BadState);
        }
        let height = u32::from_be_bytes(buf[8..12].try_into().map_err(|_| XmssError::BadState)?);
        let next = u64::from_be_bytes(buf[12..20].try_into().map_err(|_| XmssError::BadState)?);
        let seed: [u8; 32] = buf[20..52].try_into().map_err(|_| XmssError::BadState)?;
        let root: [u8; 32] = buf[52..84].try_into().map_err(|_| XmssError::BadState)?;
        let key = XmssKey::generate(seed, height);
        if key.root() != root || next > key.capacity() {
            return Err(XmssError::BadState);
        }
        Ok(XmssKey { next, ..key })
    }
}

/// Verify a signature against a tree root.
pub fn verify(root: &H32, height: u32, msg: &[u8], sig: &XmssSignature) -> bool {
    if sig.leaf >= (1u64 << height) || sig.wots.len() != LEN || sig.auth.len() != height as usize {
        return false;
    }
    let digits = digits_of(msg);
    let mut concat = Vec::with_capacity(LEN * 32);
    for i in 0..LEN {
        let end = chain(sig.wots[i], i, (W - 1) - (digits[i] as u32), digits[i] as u32);
        concat.extend_from_slice(&end);
    }
    let mut acc = h32("leaf", &[Part::Bytes(&concat)]);
    let mut idx = sig.leaf as usize;
    for sib in &sig.auth {
        acc = if idx % 2 == 0 {
            h32("node", &[Part::Bytes(&acc), Part::Bytes(sib)])
        } else {
            h32("node", &[Part::Bytes(sib), Part::Bytes(&acc)])
        };
        idx /= 2;
    }
    &acc == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("poe-xmss-test-{name}-{}", std::process::id()));
        p
    }

    #[test]
    fn sign_verify_roundtrip_and_tampering_fails() {
        let mut key = XmssKey::generate([7u8; 32], 4);
        let root = key.root();
        for msg in [&b"vote: block A"[..], b"vote: block B", b"heartbeat 12"] {
            let sig = key.sign(msg).unwrap();
            assert!(verify(&root, 4, msg, &sig));
            assert!(!verify(&root, 4, b"vote: block C", &sig), "wrong message");
            let mut bad = XmssSignature {
                leaf: sig.leaf,
                wots: sig.wots.clone(),
                auth: sig.auth.clone(),
            };
            bad.wots[0][0] ^= 1;
            assert!(!verify(&root, 4, msg, &bad), "tampered chain value");
            bad.wots.clone_from(&sig.wots);
            bad.auth[0][0] ^= 1;
            assert!(!verify(&root, 4, msg, &bad), "tampered auth path");
        }
        // No two signatures ever share a leaf.
        let mut key2 = XmssKey::generate([9u8; 32], 4);
        let indices: Vec<u64> = (0..5).map(|_| key2.sign(b"m").unwrap().leaf).collect();
        assert_eq!(indices, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn persistence_and_crash_never_reuse_a_leaf() {
        let path = tmp_path("crash");
        let _ = fs::remove_file(&path);
        let mut key = XmssKey::generate([3u8; 32], 4);
        key.save(&path).unwrap();

        let s0 = key.sign_persistent(&path, b"first").unwrap();
        assert_eq!(s0.leaf, 0);

        // Simulate a crash after the state persist but before the release:
        // reserve burns leaf 1 and persists; no signature for it ever exists.
        let burned = key.reserve(&path).unwrap();
        assert_eq!(burned, 1);
        drop(key);

        // After restart, the key resumes at 2 — leaf 1 is skipped, not reused.
        let mut key = XmssKey::load(&path).unwrap();
        assert_eq!(key.next_index(), 2);
        let s2 = key.sign_persistent(&path, b"after crash").unwrap();
        assert_eq!(s2.leaf, 2);
        assert!(verify(&key.root(), 4, b"after crash", &s2));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn exhaustion_and_bad_state_are_refused() {
        let mut key = XmssKey::generate([5u8; 32], 1); // two leaves only
        assert!(key.sign(b"a").is_ok());
        assert!(key.sign(b"b").is_ok());
        assert!(matches!(key.sign(b"c"), Err(XmssError::Exhausted)));

        let path = tmp_path("bad");
        fs::write(&path, b"not a state file").unwrap();
        assert!(matches!(XmssKey::load(&path), Err(XmssError::BadState)));
        let _ = fs::remove_file(&path);
    }
}
