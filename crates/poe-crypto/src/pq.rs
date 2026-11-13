//! Post-quantum signature and key-encapsulation carriers.
//!
//! Thin wrappers over the audited `fips204` / `fips203` implementations of
//! the NIST standards the manual names — ML-DSA-87 (FIPS 204) for general
//! signatures and ML-KEM-1024 (FIPS 203) for messaging key establishment.
//! No cryptography is implemented in this file; it fixes the wire sizes and
//! the API the rest of the node will call, so the backends stay swappable.
//! (Vote signatures do NOT use this module: they use the one-time XMSS
//! keys in [`crate::xmss`], because a vote's key must die with its use.)

use rand::rngs::ThreadRng;

// -- ML-DSA-87 (FIPS 204) ----------------------------------------------------

pub const DSA_PUBLIC_KEY_LEN: usize = 2592;
pub const DSA_SECRET_KEY_LEN: usize = 4896;
pub const DSA_SIGNATURE_LEN: usize = 4627;

pub struct DsaKeypair {
    pk: fips204::ml_dsa_87::PublicKey,
    sk: fips204::ml_dsa_87::PrivateKey,
}

impl DsaKeypair {
    pub fn generate(rng: &mut ThreadRng) -> DsaKeypair {
        let (pk, sk) = fips204::ml_dsa_87::try_keygen_with_rng(rng).expect("ML-DSA-87 keygen");
        DsaKeypair { pk, sk }
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        use fips204::traits::SerDes;
        self.pk.clone().into_bytes().to_vec()
    }

    /// Hedged signing (the FIPS 204 default with an RNG): the signature is
    /// randomized, so signing the same message twice gives different bytes.
    pub fn sign(&self, rng: &mut ThreadRng, msg: &[u8]) -> Vec<u8> {
        use fips204::traits::Signer;
        self.sk
            .try_sign_with_rng(rng, msg, &[])
            .expect("ML-DSA-87 sign")
            .to_vec()
    }

    /// The secret key's serialized bytes — for persistence in the node's
    /// own key store (a file the node operator protects; never a wire
    /// format, never logged).
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        use fips204::traits::SerDes;
        self.sk.clone().into_bytes().to_vec()
    }

    /// Rebuild a keypair from serialized public + secret key bytes.
    pub fn from_key_bytes(pk_bytes: &[u8], sk_bytes: &[u8]) -> Option<DsaKeypair> {
        use fips204::traits::SerDes;
        let pk_arr: [u8; DSA_PUBLIC_KEY_LEN] = pk_bytes.try_into().ok()?;
        let sk_arr: [u8; DSA_SECRET_KEY_LEN] = sk_bytes.try_into().ok()?;
        let pk = fips204::ml_dsa_87::PublicKey::try_from_bytes(pk_arr).ok()?;
        let sk = fips204::ml_dsa_87::PrivateKey::try_from_bytes(sk_arr).ok()?;
        Some(DsaKeypair { pk, sk })
    }
}

pub fn dsa_verify(pk_bytes: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use fips204::traits::{SerDes, Verifier};
    if pk_bytes.len() != DSA_PUBLIC_KEY_LEN || sig.len() != DSA_SIGNATURE_LEN {
        return false;
    }
    let pk_arr: [u8; DSA_PUBLIC_KEY_LEN] = match pk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_arr: [u8; DSA_SIGNATURE_LEN] = match sig.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    match fips204::ml_dsa_87::PublicKey::try_from_bytes(pk_arr) {
        Ok(pk) => pk.verify(msg, &sig_arr, &[]),
        Err(_) => false,
    }
}

// -- ML-KEM-1024 (FIPS 203) --------------------------------------------------

pub const KEM_ENCAPS_KEY_LEN: usize = 1568;
pub const KEM_CIPHERTEXT_LEN: usize = 1568;
pub const KEM_SHARED_SECRET_LEN: usize = 32;

pub struct KemKeypair {
    ek: fips203::ml_kem_1024::EncapsKey,
    dk: fips203::ml_kem_1024::DecapsKey,
}

impl KemKeypair {
    pub fn generate(rng: &mut ThreadRng) -> KemKeypair {
        use fips203::traits::KeyGen;
        let (ek, dk) =
            fips203::ml_kem_1024::KG::try_keygen_with_rng(rng).expect("ML-KEM-1024 keygen");
        KemKeypair { ek, dk }
    }

    pub fn encaps_key_bytes(&self) -> Vec<u8> {
        use fips203::traits::SerDes;
        self.ek.clone().into_bytes().to_vec()
    }

    pub fn decapsulate(&self, ct: &[u8]) -> Option<Vec<u8>> {
        use fips203::traits::{Decaps, SerDes};
        if ct.len() != KEM_CIPHERTEXT_LEN {
            return None;
        }
        let ct_arr: [u8; KEM_CIPHERTEXT_LEN] = ct.try_into().ok()?;
        let ct_obj = fips203::ml_kem_1024::CipherText::try_from_bytes(ct_arr).ok()?;
        let ss = self.dk.try_decaps(&ct_obj).ok()?;
        Some(ss.into_bytes().to_vec())
    }
}

/// Encapsulate to a peer's encapsulation key: returns (ciphertext, secret).
pub fn kem_encapsulate(rng: &mut ThreadRng, ek_bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    use fips203::traits::{Encaps, SerDes};
    if ek_bytes.len() != KEM_ENCAPS_KEY_LEN {
        return None;
    }
    let ek_arr: [u8; KEM_ENCAPS_KEY_LEN] = ek_bytes.try_into().ok()?;
    let ek = fips203::ml_kem_1024::EncapsKey::try_from_bytes(ek_arr).ok()?;
    let (ss, ct) = ek.try_encaps_with_rng(rng).ok()?;
    Some((ct.into_bytes().to_vec(), ss.into_bytes().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_dsa_87_sign_verify() {
        let mut rng = rand::thread_rng();
        let kp = DsaKeypair::generate(&mut rng);
        let pk = kp.public_key_bytes();
        assert_eq!(pk.len(), DSA_PUBLIC_KEY_LEN);
        let sig = kp.sign(&mut rng, b"join: machine 7");
        assert_eq!(sig.len(), DSA_SIGNATURE_LEN);
        assert!(dsa_verify(&pk, b"join: machine 7", &sig));
        assert!(!dsa_verify(&pk, b"join: machine 8", &sig));
        let other = DsaKeypair::generate(&mut rng);
        assert!(!dsa_verify(&other.public_key_bytes(), b"join: machine 7", &sig));
        assert!(!dsa_verify(&pk, b"join: machine 7", &sig[..100]));
    }

    #[test]
    fn ml_kem_1024_roundtrip() {
        let mut rng = rand::thread_rng();
        let alice = KemKeypair::generate(&mut rng);
        let ek = alice.encaps_key_bytes();
        assert_eq!(ek.len(), KEM_ENCAPS_KEY_LEN);
        let (ct, ss1) = kem_encapsulate(&mut rng, &ek).expect("encapsulate");
        assert_eq!(ct.len(), KEM_CIPHERTEXT_LEN);
        assert_eq!(ss1.len(), KEM_SHARED_SECRET_LEN);
        let ss2 = alice.decapsulate(&ct).expect("decapsulate");
        assert_eq!(ss1, ss2);
        // A different keypair decapsulates to a different secret (implicit
        // rejection means it still returns bytes — they just won't match).
        let bob = KemKeypair::generate(&mut rng);
        let ss3 = bob.decapsulate(&ct).expect("implicit rejection returns a secret");
        assert_ne!(ss1, ss3);
    }
}
