//! Step 7 batteries: the F-Clone drill, quota floods, revocation at both
//! levels, forgery and expiry, and the relay-only classification.

use poe_crypto::pq::DsaKeypair;
use poe_identity::*;

fn setup(quota: u64) -> (IdentityRegistry, DsaKeypair, rand::rngs::ThreadRng) {
    let mut rng = rand::thread_rng();
    let root = DsaKeypair::generate(&mut rng);
    let mut reg = IdentityRegistry::new();
    reg.admit_root(RootAdmission { root_id: 7, root_pk: root.public_key_bytes(), quota_per_epoch: quota });
    (reg, root, rng)
}

fn attest(root: &DsaKeypair, rng: &mut rand::rngs::ThreadRng, serial: u64) -> (Attestation, Vec<u8>) {
    let device = DsaKeypair::generate(rng);
    let pk = device.public_key_bytes();
    (Attestation::issue(root, rng, pk.clone(), 7, serial, 1000), pk)
}

/// THE F-CLONE DRILL: key material cloned onto a second device — the
/// same device key under another machine — cannot bind, and cannot earn.
/// Only the originally bound body earns.
#[test]
fn f_clone_drill() {
    let (mut reg, root, mut rng) = setup(100);
    let (att, _pk) = attest(&root, &mut rng, 42);

    reg.bind(&att, 1, 0).expect("the original body binds");
    assert!(reg.can_earn(1));

    // The clone: identical key material, identical attestation, another
    // machine number.
    let err = reg.bind(&att, 2, 0).expect_err("the clone must be refused");
    assert_eq!(err, IdentityError::CloneAttempt);
    assert!(!reg.can_earn(2), "the clone body does not earn");
    assert!(reg.can_earn(1), "the original still does");

    // The same body re-presenting is not a clone; it is idempotent.
    reg.bind(&att, 1, 0).expect("same body, same machine");
}

/// A quota flood from one root is bounded by the root's per-epoch quota,
/// and the quota is per root, not global.
#[test]
fn quota_flood_is_bounded_per_root() {
    let (mut reg, root, mut rng) = setup(3);
    for i in 0..3u64 {
        let (att, _) = attest(&root, &mut rng, 100 + i);
        reg.bind(&att, 1000 + i, 5).expect("within quota");
    }
    let (att4, _) = attest(&root, &mut rng, 200);
    assert_eq!(reg.bind(&att4, 2000, 5), Err(IdentityError::QuotaExceeded));
    // The next epoch has a fresh quota.
    reg.bind(&att4, 2000, 6).expect("a new epoch, a new quota");
}

#[test]
fn forgery_expiry_and_revocation() {
    let (mut reg, root, mut rng) = setup(100);
    let (att, _) = attest(&root, &mut rng, 1);

    // A tampered statement (serial changed after signing) fails.
    let mut forged = att.clone();
    forged.serial = 999;
    assert_eq!(reg.verify(&forged, 0), Err(IdentityError::BadSignature));
    // A signature from a different (unadmitted) key fails too.
    let other = DsaKeypair::generate(&mut rng);
    let wrong_root = Attestation::issue(&other, &mut rng, att.device_pk.clone(), 7, 1, 1000);
    assert_eq!(reg.verify(&wrong_root, 0), Err(IdentityError::BadSignature));
    // Expiry.
    assert_eq!(reg.verify(&att, 1001), Err(IdentityError::Expired));
    // Unknown root.
    let mut alien = att.clone();
    alien.root_id = 99;
    assert_eq!(reg.verify(&alien, 0), Err(IdentityError::UnknownRoot));

    // Bind, then revoke the device: earning stops.
    let dev = reg.bind(&att, 9, 0).unwrap();
    assert!(reg.can_earn(9));
    reg.revoke_device(dev);
    assert!(!reg.can_earn(9));
    assert_eq!(reg.bind(&att, 9, 1), Err(IdentityError::DeviceRevoked));

    // Root revocation stops every device under it.
    let (att2, _) = attest(&root, &mut rng, 2);
    reg.bind(&att2, 10, 0).unwrap();
    assert!(reg.can_earn(10));
    reg.revoke_root(7);
    assert!(!reg.can_earn(10));
    assert_eq!(reg.verify(&att2, 0), Err(IdentityError::RootRevoked));
}

#[test]
fn no_attestation_means_relay_only() {
    let (reg, root, mut rng) = setup(100);
    assert_eq!(reg.classify(None, 0), Mode::RelayOnly);
    let (att, _) = attest(&root, &mut rng, 5);
    assert_eq!(reg.classify(Some(&att), 0), Mode::Full);
    // A forged attestation classifies as relay-only, not full.
    let mut forged = att.clone();
    forged.serial = 6;
    assert_eq!(reg.classify(Some(&forged), 0), Mode::RelayOnly);
    // Relay-only devices may still relay.
    assert!(reg.may_relay(12345));
}
