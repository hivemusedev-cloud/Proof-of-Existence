//! Addition #2 batteries (2026-11-17): the Merkle companion root —
//! liveness proofs for live notes, death proofs for spent ones,
//! absence at the deaths section's edges, and tamper refusal.

use poe_kernel::ledger::{Ledger, Note, Op};
use poe_kernel::COIN;
use poe_store::merkle::*;

fn note(cm: u64, nf: u64, asset: u64, value: u64, born: u64) -> Note {
    Note { cm, nf, asset, value, born }
}

/// Two machines join (marks 1/101 and 2/102); epoch 0 closes with a
/// cap of 100,000. A join's note is a registration mark, not a
/// spendable note: what the close births is the grant stamped on
/// those marks. Returns the ledger and the two stamped grant notes.
fn joined_ledger() -> (Ledger, Note, Note) {
    let mut l = Ledger::genesis();
    l = l.act(&Op::Join { machine: 1, operator: 11, note: note(1, 101, COIN, 40, 0) });
    l = l.act(&Op::Join { machine: 2, operator: 22, note: note(2, 102, COIN, 40, 0) });
    l = l.act(&Op::Tick { cap: 100_000 });
    let a = *l.births.iter().find(|n| n.cm == 1).expect("machine 1's grant is born");
    let b = *l.births.iter().find(|n| n.cm == 2).expect("machine 2's grant is born");
    assert_eq!(a.value, 100_000, "the genesis ceiling binds the first grants");
    (l, a, b)
}

#[test]
fn genesis_companion_is_deterministic_and_the_reserve_proves_live() {
    let l = Ledger::genesis();
    let root = companion_root(&l);
    assert_eq!(root, companion_root(&l), "a pure function of the ledger");
    let reserve = l.births[0];
    let proof = prove_note(&l, reserve.cm).expect("the reserve note is live at genesis");
    assert!(verify_note_proof(&root, &proof));
    // No deaths yet: any nullifier's absence proves against the
    // deaths section.
    let s = companion_sections(&l);
    assert!(s.deaths.is_empty());
    let abs = s.deaths.absence(999_999).expect("absent from an empty section");
    assert!(verify_absence(&s.deaths_root, 999_999, &abs, death_leaf));
}

#[test]
fn a_spend_moves_the_note_from_births_to_deaths() {
    let (mut l, a, b) = joined_ledger();
    let root_before = companion_root(&l);
    let proof_a = prove_note(&l, a.cm).expect("a is live before the spend");
    assert!(verify_note_proof(&root_before, &proof_a));

    // Spend a into c; epoch 1 closes.
    let c = note(3, 103, COIN, a.value, 1);
    l = l.act(&Op::Transfer { ins: vec![a], outs: vec![c] });
    assert!(l.deaths.contains(&a.nf), "the spend must land: a's nullifier dies");
    l = l.act(&Op::Tick { cap: 0 });
    let root_after = companion_root(&l);
    assert_ne!(root_before, root_after, "the companion root moves with the state");

    // a is dead now: no liveness proof, a death proof instead.
    assert!(prove_note(&l, a.cm).is_none(), "a spent note has no liveness proof");
    let death = prove_death(&l, a.nf).expect("a's nullifier stands in deaths");
    assert!(verify_death_proof(&root_after, &death));
    // And its absence can no longer be proved.
    let s = companion_sections(&l);
    assert!(s.deaths.absence(a.nf).is_none(), "a present nullifier has no absence proof");

    // b and c are live under the new root; a's old proof is worthless
    // against it.
    assert!(verify_note_proof(&root_after, &prove_note(&l, b.cm).unwrap()));
    assert!(verify_note_proof(&root_after, &prove_note(&l, c.cm).unwrap()));
    assert!(!verify_note_proof(&root_after, &proof_a), "a stale proof fails a moved root");
}

#[test]
fn tampered_proofs_fail() {
    let (l, a, _) = joined_ledger();
    let root = companion_root(&l);
    let proof = prove_note(&l, a.cm).unwrap();

    let mut bad = proof.clone();
    bad.note.value = 41;
    assert!(!verify_note_proof(&root, &bad), "the path binds the note's value");

    let mut bad = proof.clone();
    bad.births.siblings[0][0] ^= 1;
    assert!(!verify_note_proof(&root, &bad), "a forged sibling fails");

    let mut bad = proof.clone();
    bad.deaths_root = [9u8; 64];
    assert!(!verify_note_proof(&root, &bad), "section roots must compose to the companion");

    let other = companion_root(&Ledger::genesis());
    assert!(!verify_note_proof(&other, &proof), "a proof is only good for its own root");
}

#[test]
fn absence_at_every_edge_and_inclusion_at_every_position() {
    // A ledger with several deaths (spend a chain of notes) and
    // several live notes with commitments in scrambled order. The
    // chain starts from machine 9's stamped grant and carries its
    // value along (the kernel's shape rule refuses value-0 outs).
    let mut l = Ledger::genesis();
    l = l.act(&Op::Join { machine: 9, operator: 99, note: note(50, 500, COIN, 40, 0) });
    l = l.act(&Op::Tick { cap: 100_000 });
    let mut cur = *l.births.iter().find(|n| n.cm == 50).expect("the grant is born");
    let mut spent_nfs = Vec::new();
    for e in 0..5u64 {
        let out = note(50 + (e + 1) * 7, 500 + (e + 1) * 7, COIN, cur.value, l.now);
        l = l.act(&Op::Transfer { ins: vec![cur], outs: vec![out] });
        assert!(l.deaths.contains(&cur.nf), "chain spend {e} must land");
        spent_nfs.push(cur.nf);
        cur = out;
        l = l.act(&Op::Tick { cap: 0 });
    }
    // More live notes, commitments deliberately out of order.
    for (i, cm) in [900u64, 3, 450, 12, 77].iter().enumerate() {
        let n = note(*cm, 5000 + i as u64, COIN, 5, l.now);
        l = l.act(&Op::Join { machine: 100 + i as u64, operator: 1, note: n });
    }
    l = l.act(&Op::Tick { cap: 0 });
    let root = companion_root(&l);
    let s = companion_sections(&l);

    // Every live note proves, wherever it sits in the sorted order.
    let live_count = l
        .births
        .iter()
        .filter(|n| poe_kernel::ledger::alive_at(l.now, n) && !l.deaths.contains(&n.nf))
        .count();
    // The reserve, the chain's head, and the five late joins' stamped
    // grants: exactly seven live notes.
    assert!(live_count >= 7, "the battery needs a populated live set, got {live_count}");
    for n in l.births.iter().filter(|n| {
        poe_kernel::ledger::alive_at(l.now, n) && !l.deaths.contains(&n.nf)
    }) {
        let p = prove_note(&l, n.cm).expect("every live note proves");
        assert!(verify_note_proof(&root, &p), "cm {} must verify", n.cm);
    }
    // Every spent nullifier proves its death.
    for nf in &spent_nfs {
        let d = prove_death(&l, *nf).expect("every death proves");
        assert!(verify_death_proof(&root, &d));
    }
    // Absence below the least death, above the greatest, and in the
    // gaps between.
    let absent = [
        spent_nfs[0] - 1,
        spent_nfs[spent_nfs.len() - 1] + 1,
        spent_nfs[1] + 3, // spent nfs step by 7, so +3 is a gap
    ];
    for nf in absent {
        let abs = s.deaths.absence(nf).expect("absent");
        assert!(verify_absence(&s.deaths_root, nf, &abs, death_leaf), "nf {nf} absent");
        // The same proof offered for a PRESENT key fails: a gap
        // proof covers exactly its open interval (pred, succ), and
        // every present key sits at or outside an endpoint. (Keys
        // inside the same gap verify too — that is the sorted
        // construction working as designed, not a flaw.)
        for present in &spent_nfs {
            assert!(
                !verify_absence(&s.deaths_root, *present, &abs, death_leaf),
                "an absence proof must never cover present nf {present}"
            );
        }
    }
}
