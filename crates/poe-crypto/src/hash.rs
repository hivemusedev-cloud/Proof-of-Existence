//! `H` — the seed-exact domain-separated hash, and Merkle commitments over it.
//!
//! Byte-for-byte the Compute Seed's construction (`physos_fabric/hashing.py`,
//! which mirrors the actuation seed's `H`): SHAKE256 is fed `b"PoE/" + tag`,
//! then each part framed as a 4-byte big-endian length followed by the part's
//! bytes; a natural-number part is encoded in 64-byte big-endian. The output
//! is 64 bytes (512 bits), read big-endian where a number is needed.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// A 512-bit hash value.
pub type H512 = [u8; 64];

/// One part of a hash input: raw bytes, or a natural number (encoded in
/// 64-byte big-endian, as the seed encodes every integer part).
pub enum Part<'a> {
    Bytes(&'a [u8]),
    Nat(u64),
}

/// The seed's `H`: SHAKE256 under the domain tag `b"PoE/" + tag`, parts
/// length-framed, 512-bit output.
pub fn h(tag: &str, parts: &[Part]) -> H512 {
    let mut hasher = Shake256::default();
    hasher.update(b"PoE/");
    hasher.update(tag.as_bytes());
    for part in parts {
        match part {
            Part::Bytes(b) => {
                hasher.update(&(b.len() as u32).to_be_bytes());
                hasher.update(b);
            }
            Part::Nat(v) => {
                let mut enc = [0u8; 64];
                enc[56..].copy_from_slice(&v.to_be_bytes());
                hasher.update(&64u32.to_be_bytes());
                hasher.update(&enc);
            }
        }
    }
    let mut out = [0u8; 64];
    hasher.finalize_xof().read(&mut out);
    out
}

/// `H` read as a kernel height/score: the first 8 bytes, big-endian.
pub fn h_u64(tag: &str, parts: &[Part]) -> u64 {
    let d = h(tag, parts);
    u64::from_be_bytes(d[..8].try_into().expect("64-byte digest"))
}

/// The seed's Merkle root over hash values: pairs hashed with
/// `H(b"merkle", l, r)`; an odd node is carried up unchanged; the empty
/// tree's root is `H(b"merkle-empty")`.
pub fn merkle_root(leaves: &[H512]) -> H512 {
    if leaves.is_empty() {
        return h("merkle-empty", &[]);
    }
    let mut level: Vec<H512> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(h("merkle", &[Part::Bytes(&level[i]), Part::Bytes(&level[i + 1])]));
            } else {
                next.push(level[i]);
            }
            i += 2;
        }
        level = next;
    }
    level[0]
}

fn merkle_levels(leaves: &[H512]) -> Vec<Vec<H512>> {
    let mut levels = vec![leaves.to_vec()];
    while levels.last().map(|l| l.len()) > Some(1) {
        let cur = levels.last().expect("levels nonempty").clone();
        let mut next = Vec::with_capacity((cur.len() + 1) / 2);
        let mut i = 0;
        while i < cur.len() {
            if i + 1 < cur.len() {
                next.push(h("merkle", &[Part::Bytes(&cur[i]), Part::Bytes(&cur[i + 1])]));
            } else {
                next.push(cur[i]);
            }
            i += 2;
        }
        levels.push(next);
    }
    levels
}

/// The seed's inclusion proof for leaf `i`: the siblings on the way to the
/// root, each with whether it stands on the left.
pub fn merkle_proof(leaves: &[H512], mut i: usize) -> Vec<(H512, bool)> {
    let levels = merkle_levels(leaves);
    let mut proof = Vec::new();
    for lvl in &levels[..levels.len().saturating_sub(1)] {
        let sib = i ^ 1;
        if sib < lvl.len() {
            proof.push((lvl[sib], sib < i));
        }
        i /= 2;
    }
    proof
}

/// Verify an inclusion proof against a root, exactly as the seed does.
pub fn merkle_verify(root: &H512, leaf: &H512, proof: &[(H512, bool)]) -> bool {
    let mut acc = *leaf;
    for (sib, left) in proof {
        acc = if *left {
            h("merkle", &[Part::Bytes(sib), Part::Bytes(&acc)])
        } else {
            h("merkle", &[Part::Bytes(&acc), Part::Bytes(sib)])
        };
    }
    &acc == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn h_matches_the_python_seed_vectors() {
        // Generated with hashlib.shake_256 under the seed's exact framing.
        assert_eq!(
            hex(&h("merkle-empty", &[])),
            "a9f2c291fb8cef7e40ff1f9a5140235b0f84336ec59a29f807924599e35a9ddec7055271574b26485e375fbefb4118f44250cf3f22c406a7d2350279db2b671d"
        );
        assert_eq!(
            hex(&h("merkle", &[Part::Nat(1), Part::Nat(2)])),
            "5f894e2fb78d22c9d721c5cdd527af1bc37d4a0caef33144deafcd1ba1beb32ef0138756ae8437aab42b146fada8c18aac1e699f4bf468915cf5c23287de72e5"
        );
        assert_eq!(
            hex(&h("note", &[Part::Nat(7), Part::Nat(2001)])),
            "6ea998134f464b48a5b61453b6992550ff5c7dc76971e31758ff66f11b455d1eb444d36cb45ca5ba7f6746d0e97a7ae330d16580a9bcb1f9d22d79f75b69cd8d"
        );
        assert_eq!(
            hex(&h("ticket", &[Part::Bytes(b"beacon"), Part::Nat(42)])),
            "a37ecf262a89e7c46c7dae26595220d72a9df1a60c4057e7a9a3fa435eef1b9a01a8e460de215d4f027416610f31aeb4acfcc6344f018762dc724bd94ac6af1d"
        );
        // Domain separation: same parts, different tag, different hash.
        assert_ne!(h("note", &[Part::Nat(7)]), h("vote", &[Part::Nat(7)]));
        // Framing: [1, 23] and [12, 3] as byte parts must not collide.
        assert_ne!(
            h("x", &[Part::Bytes(&[1, 23])]),
            h("x", &[Part::Bytes(&[12, 3])])
        );
    }

    #[test]
    fn merkle_roundtrip_and_odd_carry() {
        let leaves: Vec<H512> = (0..13u64).map(|i| h("leaf", &[Part::Nat(i)])).collect();
        let root = merkle_root(&leaves);
        for i in 0..leaves.len() {
            let proof = merkle_proof(&leaves, i);
            assert!(merkle_verify(&root, &leaves[i], &proof), "leaf {i}");
        }
        // A leaf not in the tree does not verify.
        let other = h("leaf", &[Part::Nat(999)]);
        assert!(!merkle_verify(&root, &other, &merkle_proof(&leaves, 0)));
        // Empty tree root is the seed's constant.
        assert_eq!(merkle_root(&[]), h("merkle-empty", &[]));
    }
}
