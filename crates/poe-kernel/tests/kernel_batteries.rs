//! Acceptance batteries for poe-kernel, modelled on the Fortran twin's
//! batteries (T1 streams, T2 interleavings, evidence and ledger checks) and
//! on the Lean theorems they mirror (`settle_nodup`, `settle_canonical`,
//! `merge_registers_the_union`, `evidence_is_complete`, the cap and the
//! grant law). Deterministic: one xorshift64 stream, the twin's own seed.

use poe_kernel::ledger::{live_a, Ledger, Note, Op};
use poe_kernel::*;
use std::collections::BTreeSet;

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn as_set(xs: &[u64]) -> BTreeSet<u64> {
    xs.iter().copied().collect()
}

#[test]
fn t1_streams_no_height_twice_and_canonical() {
    // Twin T1 shape: 200 streams x 5,000 spends over a contended height range.
    let mut rng = XorShift(88172645463325252);
    for _ in 0..200 {
        let stream: Vec<Spend> = (0..5000)
            .map(|_| Spend::new(rng.next(), rng.below(3000)))
            .collect();
        let accepted = settle(&[], &stream);
        let acc_nfs = nfs(&accepted);
        assert!(nodup_b(&acc_nfs), "a height was accepted twice");
        // Canonical: every accepted spend is the first on its height.
        for s in &accepted {
            assert_eq!(first_tx(&stream, s.nf), s.tx);
        }
        // Register = exactly the accepted heights.
        assert_eq!(as_set(&register(&[], &stream)), as_set(&acc_nfs));
    }
}

#[test]
fn t2_interleavings_register_the_union() {
    // Twin T2 / theorem `merge_registers_the_union`: settle two offline
    // branches in either order; the registered height set is the union,
    // identical in both orders. Only the winning side may differ.
    let mut rng = XorShift(88172645463325252);
    for _ in 0..200 {
        let a: Vec<Spend> = (0..500)
            .map(|_| Spend::new(rng.next(), rng.below(800)))
            .collect();
        let b: Vec<Spend> = (0..500)
            .map(|_| Spend::new(rng.next(), rng.below(800)))
            .collect();
        let ab = register(&register(&[], &a), &b);
        let ba = register(&register(&[], &b), &a);
        assert_eq!(as_set(&ab), as_set(&ba));
        let expect: BTreeSet<u64> = as_set(&nfs(&a)).union(&as_set(&nfs(&b))).copied().collect();
        assert_eq!(as_set(&ab), expect);
    }
}

#[test]
fn evidence_names_exactly_the_noncanonical_sides() {
    // `evidence_is_complete` + `evidence_is_two_sides_one_height`: plant a
    // canonical spend per height, then k second sides; evidence must be
    // exactly those k pairs, same height, different side, canonical first.
    let canonical: Vec<Spend> = (0..100).map(|i| Spend::new(10_000 + i, i)).collect();
    let offenders: Vec<Spend> = (0..50).map(|i| Spend::new(99_000 + i, i * 2)).collect();
    let mut candidates = canonical.clone();
    candidates.extend_from_slice(&offenders);
    let ev = evidence(&canonical, &candidates);
    assert_eq!(ev.len(), offenders.len());
    for (canon, off) in &ev {
        assert_eq!(canon.nf, off.nf);
        assert_ne!(canon.tx, off.tx);
        assert_eq!(canon.tx, first_tx(&canonical, off.nf));
    }
    // The stateful Registry agrees.
    let mut reg = Registry::new(RegistryKind::CoinDeath);
    for s in &canonical {
        assert_eq!(reg.claim(*s), ClaimOutcome::Accepted);
    }
    for s in &canonical {
        assert_eq!(reg.claim(*s), ClaimOutcome::Duplicate);
    }
    for s in &offenders {
        assert_eq!(reg.claim(*s), ClaimOutcome::Evidence);
    }
    assert_eq!(reg.evidence().len(), offenders.len());
    assert_eq!(reg.accepted(), canonical.as_slice());
}

#[test]
fn multi_spend_is_all_or_nothing() {
    let r0: Vec<u64> = vec![];
    let good = MultiSpend { tx: 1, hs: vec![10, 11, 12] };
    let dup_inside = MultiSpend { tx: 2, hs: vec![20, 20] };
    let overlap = MultiSpend { tx: 3, hs: vec![12, 13] };
    let fresh = MultiSpend { tx: 4, hs: vec![13, 14] };
    let stream = vec![good.clone(), dup_inside, overlap, fresh.clone()];
    let accepted = settle_m(&r0, &stream);
    assert_eq!(accepted, vec![good, fresh]);
    assert_eq!(
        as_set(&register_m(&r0, &stream)),
        as_set(&[10, 11, 12, 13, 14])
    );
}

#[test]
fn money_law_bounds() {
    assert_eq!(pot(0), SMAX / 300);
    assert_eq!(pot(SMAX), 0);
    // GMAX binds before the pot for a lone claimant at genesis.
    assert_eq!(grant(0, 1, u64::MAX), GMAX);
    // A module cap can only lower the grant.
    assert_eq!(grant(0, 1, 7), 7);
    // Lean Nat division: zero claimants -> zero share, zero emission.
    assert_eq!(pot_share(0, 0), 0);
    assert_eq!(emission(0, 0, u64::MAX), 0);
    assert_eq!(emission(0, 3, u64::MAX), 3 * GMAX as u128);
}

fn note(cm: u64, nf: u64, asset: u64, value: u64, born: u64) -> Note {
    Note { cm, nf, asset, value, born }
}

#[test]
fn ledger_genesis_join_tick_transfer() {
    let g = Ledger::genesis();
    assert_eq!(live_a(&g, COIN), RESERVE);
    assert_eq!(g.minted, RESERVE);

    // Join machine 7, naming fresh grant marks; a second join of the same
    // machine is invalid and changes nothing.
    let grant_note = note(1001, 2001, COIN, 0, 0);
    let l1 = g.act(&Op::Join { machine: 7, operator: 7, note: grant_note });
    assert_eq!(l1.machines, vec![7]);
    let l1b = l1.act(&Op::Join { machine: 7, operator: 9, note: note(1002, 2002, COIN, 0, 0) });
    assert_eq!(l1b, l1, "duplicate join must leave the ledger unchanged");

    // Close the epoch with no module cap: the registration is born as a
    // grant note of value grant(live, 1, MAX) = GMAX, born at epoch 0.
    let l2 = l1.act(&Op::Tick { cap: u64::MAX });
    assert_eq!(l2.now, 1);
    assert!(l2.regs.is_empty());
    let born = l2.births[0];
    assert_eq!(born, note(1001, 2001, COIN, GMAX, 0));
    assert_eq!(l2.minted, RESERVE + GMAX as u128);

    // Spend the grant note: split it into two fresh notes, value conserved.
    let out1 = note(3001, 4001, COIN, 150_000_000, 1);
    let out2 = note(3002, 4002, COIN, 250_000_000, 1);
    let l3 = l2.act(&Op::Transfer { ins: vec![born], outs: vec![out1, out2] });
    assert!(l3.deaths.contains(&2001));
    assert_eq!(live_a(&l3, COIN), RESERVE + GMAX as u128);

    // The same input spent again is refused: ledger unchanged.
    let l4 = l3.act(&Op::Transfer {
        ins: vec![born],
        outs: vec![note(3003, 4003, COIN, GMAX, 1)],
    });
    assert_eq!(l4, l3, "double spend must leave the ledger unchanged");

    // A transfer that does not conserve value is refused.
    let l5 = l3.act(&Op::Transfer {
        ins: vec![out1],
        outs: vec![note(3004, 4004, COIN, 1, 1)],
    });
    assert_eq!(l5, l3);
}

#[test]
fn ledger_assets_issue_cap_and_window() {
    let g = Ledger::genesis();
    // The coin can never be created as an asset.
    assert_eq!(g.act(&Op::Create { issuer: 1, asset: COIN, cap: 10 }), g);
    // Create asset 5 with cap 1000, issue 600, then a second issue of 500
    // exceeds the cap and is refused.
    let l1 = g.act(&Op::Create { issuer: 1, asset: 5, cap: 1000 });
    assert_ne!(l1, g);
    let issue1 = vec![note(5001, 6001, 5, 600, 0)];
    let l2 = l1.act(&Op::Issue { issuer: 1, asset: 5, outs: issue1 });
    assert_eq!(live_a(&l2, 5), 600);
    let l3 = l2.act(&Op::Issue { issuer: 1, asset: 5, outs: vec![note(5002, 6002, 5, 500, 0)] });
    assert_eq!(l3, l2, "issue beyond cap must be refused");
    // Only the issuer may issue.
    let l4 = l2.act(&Op::Issue { issuer: 2, asset: 5, outs: vec![note(5003, 6003, 5, 10, 0)] });
    assert_eq!(l4, l2);

    // Window: a note born at epoch 0 cannot be spent at epoch 600 (> 522).
    let mut old = Ledger::genesis();
    old.now = 600;
    old.births.push(note(7001, 8001, COIN, 10, 0));
    let after = old.act(&Op::Transfer {
        ins: vec![note(7001, 8001, COIN, 10, 0)],
        outs: vec![note(7002, 8002, COIN, 10, 600)],
    });
    assert_eq!(after, old, "a note outside its window must not spend");
}

#[test]
fn renewal_act_battery_r1_to_r6() {
    // Setup used by several cases: machine 7 joins in epoch 0 and its grant
    // is born at the close; epoch 1 starts with 7 registered.
    let g = Ledger::genesis();
    let e0 = g
        .act(&Op::Join { machine: 7, operator: 70, note: note(1001, 2001, COIN, 0, 0) })
        .act(&Op::Tick { cap: u64::MAX });
    assert_eq!(e0.now, 1);
    assert!(e0.claimants.is_empty(), "a close clears the epoch's claims");

    // R1: renewal by an unregistered machine changes nothing.
    let r1 = e0.act(&Op::Renew { machine: 99, operator: 99, note: note(1101, 2101, COIN, 0, 1) });
    assert_eq!(r1, e0);

    // R2: renewal naming a non-fresh note changes nothing — here the marks
    // of the grant note already born (cm 1001 / nf 2001 are in births).
    let r2 = e0.act(&Op::Renew { machine: 7, operator: 70, note: note(1001, 2001, COIN, 0, 1) });
    assert_eq!(r2, e0);

    // R3 + R6: a join (machine 8) and a renewal (machine 7) in one epoch are
    // paid alike at the close, at several module caps including 0.
    for cap in [u64::MAX, 7, 0] {
        let mixed = e0
            .act(&Op::Join { machine: 8, operator: 80, note: note(1002, 2002, COIN, 0, 1) })
            .act(&Op::Renew { machine: 7, operator: 70, note: note(1003, 2003, COIN, 0, 1) });
        assert_eq!(mixed.regs.len(), 2);
        assert_eq!(mixed.claimants.len(), 2);
        let live_before = live_a(&mixed, COIN);
        let closed = mixed.act(&Op::Tick { cap });
        let expected = poe_kernel::grant(live_before, 2, cap);
        assert_eq!(closed.births[0].value, expected, "renewal grant (cap {cap})");
        assert_eq!(closed.births[1].value, expected, "join grant (cap {cap})");
        assert_eq!(closed.births[0].asset, COIN);
        assert_eq!(closed.births[1].asset, COIN);
        assert_eq!(
            closed.minted,
            mixed.minted + 2 * expected as u128,
            "a close mints one grant per claimant (cap {cap})"
        );
    }

    // R4: a second renewal by the same machine in one epoch is refused, and
    // so is a renewal in the same epoch as its join (the Lean theorems
    // renew_then_no_renew / join_then_no_renew).
    let once = e0.act(&Op::Renew { machine: 7, operator: 70, note: note(1004, 2004, COIN, 0, 1) });
    assert_ne!(once, e0);
    let twice = once.act(&Op::Renew { machine: 7, operator: 70, note: note(1005, 2005, COIN, 0, 1) });
    assert_eq!(twice, once, "second renewal in one epoch must be refused");
    let joined = g.act(&Op::Join { machine: 9, operator: 90, note: note(1006, 2006, COIN, 0, 0) });
    let join_then_renew =
        joined.act(&Op::Renew { machine: 9, operator: 90, note: note(1007, 2007, COIN, 0, 0) });
    assert_eq!(join_then_renew, joined, "join then renew in one epoch must be refused");
    // After the close, the same machine may claim again in the new epoch.
    let next_epoch = once.act(&Op::Tick { cap: u64::MAX });
    let again = next_epoch.act(&Op::Renew { machine: 7, operator: 70, note: note(1008, 2008, COIN, 0, 2) });
    assert_ne!(again, next_epoch, "a new epoch reopens the claim");

    // R5: the renewal grant note, once born, spends exactly once through the
    // ordinary transfer path.
    let born = e0
        .act(&Op::Renew { machine: 7, operator: 70, note: note(1010, 2010, COIN, 0, 1) })
        .act(&Op::Tick { cap: u64::MAX });
    let grant_note = born.births[0];
    assert_eq!(grant_note, note(1010, 2010, COIN, GMAX, 1));
    let spent = born.act(&Op::Transfer {
        ins: vec![grant_note],
        outs: vec![note(3001, 4001, COIN, GMAX, 2)],
    });
    assert!(spent.deaths.contains(&2010));
    let respent = spent.act(&Op::Transfer {
        ins: vec![grant_note],
        outs: vec![note(3002, 4002, COIN, GMAX, 2)],
    });
    assert_eq!(respent, spent, "the renewal grant must not spend twice");

    // R6 (edge): with the pot empty (live coin at the cap), a mixed close
    // still births both grants — of value 0 — and nothing panics.
    let mut full = Ledger::genesis();
    full.births.push(note(9001, 9501, COIN, (SMAX - RESERVE) as u64, 0));
    assert_eq!(live_a(&full, COIN), SMAX);
    let full = full
        .act(&Op::Join { machine: 7, operator: 70, note: note(1001, 2001, COIN, 0, 0) })
        .act(&Op::Tick { cap: u64::MAX })
        .act(&Op::Join { machine: 8, operator: 80, note: note(1002, 2002, COIN, 0, 1) })
        .act(&Op::Renew { machine: 7, operator: 70, note: note(1003, 2003, COIN, 0, 1) })
        .act(&Op::Tick { cap: u64::MAX });
    assert_eq!(full.births[0].value, 0);
    assert_eq!(full.births[1].value, 0);
}

#[test]
fn all_ten_registries_run_the_same_law() {
    let kinds = [
        RegistryKind::CoinDeath,
        RegistryKind::MachineBirth,
        RegistryKind::Vote,
        RegistryKind::KeyUse,
        RegistryKind::Slot,
        RegistryKind::Proposal,
        RegistryKind::Admission,
        RegistryKind::ContractVersion,
        RegistryKind::OracleTick,
        RegistryKind::MessageTag,
    ];
    for kind in kinds {
        let mut r = Registry::new(kind);
        assert_eq!(r.claim(Spend::new(1, 42)), ClaimOutcome::Accepted);
        assert_eq!(r.claim(Spend::new(1, 42)), ClaimOutcome::Duplicate);
        assert_eq!(r.claim(Spend::new(2, 42)), ClaimOutcome::Evidence);
        assert!(r.is_registered(42));
        assert_eq!(r.evidence().len(), 1);
    }
}
