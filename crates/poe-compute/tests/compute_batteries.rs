//! Step 11 batteries: the kernels pinned against the Python seed itself
//! (same jobs, same parameters, same Merkle roots — computed with numpy
//! by `physos_fabric.kernels` at test-authoring time), formal ≡ executed
//! on every piece, and the triaxial audit: honest claims seal, planted
//! claims break, unregistered claims stay open, rivals break.

use poe_compute::*;
use poe_crypto::hash::H512;

fn hex64(s: &str) -> H512 {
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// The seed's own roots for these runs (see crate docs): if the port
/// drifted anywhere — stream, framing, piece layout, Merkle — these fail.
#[test]
fn kernels_match_the_python_seed() {
    let (pieces, ops) = Kernel::GemmI8.run(7, 2, &Params::gemm(4, 6, 5));
    assert_eq!(ops, 240);
    assert_eq!(
        side_of(&pieces),
        hex64("798b792375399dfc1bbfea4f2ff2f7eb78394e29732ede22da5ec499bbfcc059d66e122c53600acdce23cb48f01cc88b89435b07df10ba986a3bd928a8688926")
    );

    let (pieces, ops) = Kernel::Sieve.run(3, 1, &Params::sieve(100_000, 8));
    assert_eq!(ops, 320_891);
    assert_eq!(
        side_of(&pieces),
        hex64("1dc57af222c7d58fc66b8b8c53dbe39ee209b6923edec5bb47c440610cab067fba27d8cfa443251de824c31755e4b7cb63d5525bfd5e29dd2501b0d287bc92a4")
    );

    let (pieces, ops) = Kernel::DotF32.run(9, 1, &Params::dot(3, 5));
    assert_eq!(ops, 30);
    assert_eq!(
        side_of(&pieces),
        hex64("cca4aa98e24e9b1e18201bb92af4135aa0849c71fd2edc72001d1f1ed08d62c8b27432b465b3e5ad72c536d48fe4ad4fd6531223e748d568cd60a4c293352255")
    );

    let (pieces, ops) = Kernel::Search.run(5, 0, &Params::search(2000, 4, 14));
    assert_eq!(ops, 2000);
    assert_eq!(
        side_of(&pieces),
        hex64("d2bda45f9b0962faa98faab1ccf48f56a4d77968dacf1bd368caf0776591f199a6d94ab09a52617afdafcbbdaf34e4b8b086f12ad0d0115ae1ccab18b41fc3ca")
    );
}

/// The two roads share no code; they must agree on every piece anyway.
#[test]
fn formal_and_executed_roads_agree() {
    for (kernel, p, job, chunk) in [
        (Kernel::GemmI8, Params::gemm(5, 7, 4), 11, 3),
        (Kernel::Sieve, Params::sieve(50_000, 8), 2, 2),
        (Kernel::Search, Params::search(1500, 4, 12), 8, 1),
        (Kernel::DotF32, Params::dot(4, 9), 4, 2),
    ] {
        for i in 0..kernel.npieces(&p) {
            assert_eq!(
                kernel.piece_on(job, chunk, &p, i),
                kernel.formal(job, chunk, &p, i),
                "{kernel:?} piece {i}: the roads disagree"
            );
        }
    }
}

fn honest_claim() -> (Claim, Params, Vec<Vec<u8>>) {
    let p = Params::gemm(6, 5, 4);
    let (pieces, _) = Kernel::GemmI8.run(21, 1, &p);
    let claim = Claim::commit(77, Kernel::GemmI8, 21, 1, &p, &pieces, 900);
    (claim, p, pieces)
}

#[test]
fn honest_claim_seals() {
    let (claim, p, pieces) = honest_claim();
    let record = vec![claim.registration_spend()];
    let draw = [3u8; 64];
    assert_eq!(audit(&claim, &p, &pieces, &record, &draw), Verdict::Sealed);
    // Every piece opens against the side.
    for i in 0..pieces.len() {
        assert!(open_piece(&pieces, &claim.side, i).is_some());
    }
    assert!(open_piece(&pieces, &claim.side, pieces.len()).is_none());
}

#[test]
fn unregistered_claim_stays_open_and_rival_breaks() {
    let (claim, p, pieces) = honest_claim();
    let draw = [3u8; 64];
    // No record at all: the registration road is missing — Open, not Broken.
    assert_eq!(audit(&claim, &p, &pieces, &[], &draw), Verdict::Open { missing: "registration" });
    // A rival's spend on the same height, registered first: this claim's
    // spend comes back Evidence — Broken at Seal G.
    let mut rival = claim.clone();
    rival.side = [9u8; 64];
    let record = vec![rival.registration_spend(), claim.registration_spend()];
    match audit(&claim, &p, &pieces, &record, &draw) {
        Verdict::Broken { seal, .. } => assert_eq!(seal, "G"),
        other => panic!("expected Broken at G, got {other:?}"),
    }
}

/// The plants: one anchor moved at a time. A claim carrying a planted
/// piece (moved input) or committed under a moved specification must be
/// refused by the seals.
#[test]
fn planted_claims_break() {
    let (claim, p, pieces) = honest_claim();
    let record = vec![claim.registration_spend()];
    let draw = [3u8; 64];

    // Plant on the material: piece 2 recomputed from a row with one
    // element moved — the side no longer matches the pieces (Seal L),
    // and even recommitted, the roads would part at the probe.
    let mut planted = pieces.clone();
    planted[2] = gemm_plant_row(21, 1, &p, 2, 5);
    assert_ne!(planted[2], pieces[2], "the plant must actually move the piece");
    match audit(&claim, &p, &planted, &record, &draw) {
        Verdict::Broken { seal, .. } => assert_eq!(seal, "L"),
        other => panic!("expected Broken at L, got {other:?}"),
    }
    // Recommit the planted pieces as a fresh claim and register it: now
    // the sentence is consistent, and Seal G's roads must catch it —
    // but the probes are drawn from the beacon, so use a draw that
    // reaches piece 2 by construction of the battery: try several draws
    // and require at least one Broken at G (the audit samples; the
    // battery asserts the sampling catches a known plant).
    let planted_claim = Claim::commit(77, Kernel::GemmI8, 21, 1, &p, &planted, 900);
    let record2 = vec![planted_claim.registration_spend()];
    let mut caught = false;
    for d in 0..32u8 {
        if let Verdict::Broken { seal, .. } = audit(&planted_claim, &p, &planted, &record2, &[d; 64]) {
            assert_eq!(seal, "G");
            caught = true;
            break;
        }
    }
    assert!(caught, "some beacon draw must probe the planted piece");

    // Plant on the specification: the claim's ops are stated for other
    // parameters than the commitment's — Seal L again.
    let mut spec_moved = claim.clone();
    spec_moved.ops += 1;
    match audit(&spec_moved, &p, &pieces, &record, &draw) {
        Verdict::Broken { seal, .. } => assert_eq!(seal, "L"),
        other => panic!("expected Broken at L, got {other:?}"),
    }

    // The dot lane's plant, on its own kernel.
    let pd = Params::dot(4, 6);
    let (dpieces, _) = Kernel::DotF32.run(3, 1, &pd);
    let mut dplanted = dpieces.clone();
    dplanted[1] = dot_plant_piece(3, 1, &pd, 1, 2);
    assert_ne!(dplanted[1], dpieces[1]);
    let dclaim = Claim::commit(78, Kernel::DotF32, 3, 1, &pd, &dpieces, 900);
    let drecord = vec![dclaim.registration_spend()];
    match audit(&dclaim, &pd, &dplanted, &drecord, &draw) {
        Verdict::Broken { .. } => {}
        other => panic!("expected Broken, got {other:?}"),
    }
}
