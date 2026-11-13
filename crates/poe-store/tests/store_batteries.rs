//! Step 3 batteries: persistence, torn tails, state roots, the window
//! pruning verdict mirror, and registry persistence.

use poe_kernel::ledger::{Ledger, Note, Op};
use poe_kernel::{Registry, RegistryKind, Spend, COIN};
use poe_store::{load_registries, save_registries, Store};
use std::path::PathBuf;

fn tmp_dir(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("poe-store-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn note(cm: u64, nf: u64, asset: u64, value: u64, born: u64) -> Note {
    Note { cm, nf, asset, value, born }
}

fn sample_history() -> Vec<Op> {
    vec![
        Op::Join { machine: 1, operator: 11, note: note(1, 101, COIN, 5, 0) },
        Op::Join { machine: 2, operator: 22, note: note(2, 102, COIN, 5, 0) },
        Op::Tick { cap: 1000 },
        Op::Transfer {
            ins: vec![note(1, 101, COIN, 5, 0)],
            outs: vec![note(3, 103, COIN, 5, 1)],
        },
        Op::Renew { machine: 1, operator: 11, note: note(4, 104, COIN, 5, 1) },
        Op::Tick { cap: 1000 },
        Op::Tick { cap: 1000 },
    ]
}

#[test]
fn persistence_roundtrip_and_state_roots() {
    let dir = tmp_dir("roundtrip");
    let ops = sample_history();
    let (ledger_copy, roots_copy) = {
        let mut s = Store::open(&dir).unwrap();
        for op in &ops {
            s.apply(op).unwrap();
        }
        s.flush().unwrap();
        (s.ledger().clone(), s.roots().to_vec())
    };
    // Three closes happened (after epoch 0, 1, 2 -> roots at now 1, 2, 3).
    assert_eq!(roots_copy.len(), 3);
    assert!(roots_copy.windows(2).all(|w| w[0].1 != w[1].1), "roots must chain forward");

    let mut s = Store::open(&dir).unwrap();
    assert_eq!(s.ledger(), &ledger_copy, "replayed ledger must equal the live one");
    assert_eq!(s.roots(), roots_copy.as_slice());

    // Snapshot, then more history on top: reopening must still agree.
    s.snapshot().unwrap();
    s.apply(&Op::Tick { cap: 1000 }).unwrap();
    let after = s.ledger().clone();
    drop(s);
    let s = Store::open(&dir).unwrap();
    assert_eq!(s.ledger(), &after);
    assert_eq!(s.roots().len(), 4);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn torn_tail_is_dropped_not_applied() {
    let dir = tmp_dir("torn");
    let ops = sample_history();
    let good = {
        let mut s = Store::open(&dir).unwrap();
        for op in &ops {
            s.apply(op).unwrap();
        }
        s.flush().unwrap();
        s.ledger().clone()
    };
    // Simulate a crash mid-write: garbage bytes at the end of the log.
    let log_path = dir.join("ops.log");
    let mut raw = std::fs::read(&log_path).unwrap();
    raw.extend_from_slice(&[0xDE, 0xAD, 0x00, 0x05, 0xFF]);
    std::fs::write(&log_path, &raw).unwrap();

    let s = Store::open(&dir).unwrap();
    assert_eq!(s.ledger(), &good, "torn tail must leave the good history intact");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The T16 mirror, at battery scale: a history that runs well past the
/// 522-epoch window, then a battery of candidate acts whose verdicts must
/// agree between the full ledger and its pruned form — the Rust echo of
/// the Lean theorem `the_window_is_enough` (which proves it for inputs).
/// Candidate acts use genuinely fresh marks, as honest acts do in
/// deployment (marks are hash-derived); reusing a *forgotten* mark is the
/// one case pruning cannot see, by design, and is out of scope here.
#[test]
fn pruned_and_full_verdicts_agree_past_the_window() {
    let mut l = Ledger::genesis();
    let mut ops: Vec<Op> = Vec::new();
    // Two machines join in epoch 0 with coin notes.
    ops.push(Op::Join { machine: 1, operator: 11, note: note(1, 101, COIN, 40, 0) });
    ops.push(Op::Join { machine: 2, operator: 22, note: note(2, 102, COIN, 40, 0) });
    ops.push(Op::Create { issuer: 7, asset: 50, cap: 10_000 });
    // A transfer chain that lives and dies across epochs.
    let mut cur = note(1, 101, COIN, 40, 0);
    let mut cm = 1000u64;
    for e in 0..6u64 {
        ops.push(Op::Tick { cap: 0 }); // close the epoch (grants to machines 1,2)
        let out = note(cm, cm + 500_000, COIN, 40, e + 1);
        ops.push(Op::Transfer { ins: vec![cur], outs: vec![out] });
        cur = out;
        cm += 1;
    }
    // Issue some asset-50 value late (epoch 6).
    ops.push(Op::Issue { issuer: 7, asset: 50, outs: vec![note(9001, 9501, 50, 300, 6)] });
    for op in &ops {
        l = l.act(op);
    }
    // Run the clock far past every window: 530 epochs. Everything born at
    // epochs 0..=6 is now burned; only what the closes keep minting lives.
    for _ in 0..530 {
        l = l.act(&Op::Tick { cap: 0 });
    }
    assert!(l.now > 522 + 6, "history must pass the window, now = {}", l.now);

    let p = l.pruned();
    assert!(p.births.len() < l.births.len(), "pruning must actually forget");
    assert_eq!(p.machines, l.machines, "machine registry kept whole");
    assert_eq!(p.assets.len(), l.assets.len(), "asset registry kept whole");
    assert_eq!(
        p.assets.iter().find(|a| a.id == 50).map(|a| a.cap),
        Some(10_000 - 300),
        "kept cap is the remainder after issues"
    );

    // The input verdicts themselves (the Lean theorem's exact statement):
    for n in [
        cur,                                        // burned by now
        note(9001, 9501, 50, 300, 6),               // burned asset note
        note(1, 101, COIN, 40, 0),                  // long dead
    ] {
        assert_eq!(l.is_input_ok(&n), p.is_input_ok(&n), "inputOk must agree for {n:?}");
        assert!(!l.is_input_ok(&n));
    }

    // Act verdicts on honest candidates (fresh marks throughout):
    let fresh = |cm: u64| note(cm, cm + 700_000, COIN, 1, l.now);
    let candidates: Vec<Op> = vec![
        Op::Join { machine: 1, operator: 11, note: fresh(5001) },   // replayed join: refuse both
        Op::Join { machine: 9, operator: 99, note: fresh(5002) },   // fresh join: accept both
        Op::Renew { machine: 1, operator: 11, note: fresh(5003) },  // registered: accept both
        Op::Renew { machine: 42, operator: 1, note: fresh(5004) },  // unknown: refuse both
        Op::Create { issuer: 7, asset: 50, cap: 5 },                // existing asset: refuse both
        Op::Create { issuer: 7, asset: 60, cap: 5 },                // new asset: accept both
        Op::Issue { issuer: 7, asset: 50, outs: vec![note(9101, 9601, 50, 9_700, l.now)] }, // exactly the remainder
        Op::Issue { issuer: 7, asset: 50, outs: vec![note(9102, 9602, 50, 9_701, l.now)] }, // one over: refuse both
        Op::Transfer { ins: vec![cur], outs: vec![note(9201, 9701, COIN, 40, l.now)] },     // burned input: refuse both
        Op::Transfer { ins: vec![note(1, 101, COIN, 40, 0)], outs: vec![note(9202, 9702, COIN, 40, l.now)] }, // dead input: refuse both
    ];
    for op in &candidates {
        assert_eq!(l.accepts(op), p.accepts(op), "verdicts must agree for {op:?}");
    }
    // And the agreed verdicts are the expected ones, not just equal:
    assert!(!l.accepts(&candidates[0]));
    assert!(l.accepts(&candidates[1]));
    assert!(l.accepts(&candidates[2]));
    assert!(!l.accepts(&candidates[3]));
    assert!(!l.accepts(&candidates[4]));
    assert!(l.accepts(&candidates[5]));
    assert!(l.accepts(&candidates[6]), "issue exactly to the kept remainder");
    assert!(!l.accepts(&candidates[7]));
    assert!(!l.accepts(&candidates[8]));
    assert!(!l.accepts(&candidates[9]));
}

#[test]
fn registry_persistence_with_evidence() {
    let dir = tmp_dir("registries");
    use RegistryKind::*;
    let kinds = [
        CoinDeath, MachineBirth, Vote, KeyUse, Slot, Proposal, Admission, ContractVersion,
        OracleTick, MessageTag,
    ];
    let mut regs: Vec<Registry> = kinds.iter().map(|&k| Registry::new(k)).collect();
    for r in regs.iter_mut() {
        r.claim(Spend { tx: 1, nf: 10 });
        r.claim(Spend { tx: 2, nf: 20 });
        if r.kind == RegistryKind::Vote {
            // A double show: evidence recorded, heights unchanged by the pair.
            assert_eq!(r.claim(Spend { tx: 3, nf: 20 }), poe_kernel::ClaimOutcome::Evidence);
        }
    }
    save_registries(&dir, &regs).unwrap();
    let loaded = load_registries(&dir).unwrap();
    assert_eq!(loaded.len(), 10);
    for (a, b) in regs.iter().zip(loaded.iter()) {
        assert_eq!(a.kind, b.kind);
        assert_eq!(a.heights(), b.heights());
        assert_eq!(a.accepted(), b.accepted());
        assert_eq!(a.evidence(), b.evidence());
    }
    let _ = std::fs::remove_dir_all(&dir);
}
