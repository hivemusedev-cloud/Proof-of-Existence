//! Step 6 batteries: the tokenomics law's own numbers, a close on the
//! real kernel ledger, vesting, the first-year envelope under a join
//! flood, renewal eligibility, and an aggregate 40-year replay.

use poe_epoch::*;
use poe_kernel::ledger::{Ledger, Note, Op};
use poe_kernel::{RESERVE, COIN, SMAX};

fn note(cm: u64, nf: u64, value: u64, born: u64) -> Note {
    Note { cm, nf, asset: COIN, value, born }
}

#[test]
fn the_laws_own_numbers() {
    // "The ceiling at genesis is a hundred thousand coins."
    assert_eq!(ceiling(0), 100_000);
    // The budget: Genesis floor, and the phases meet without a step.
    assert_eq!(budget(0), EBOOT);
    assert_eq!(budget(500_000_000_000), EBOOT, "still floored at the CGG threshold");
    assert_eq!(budget(100_000_000_000_000), 2_000_000_000_000, "Growth meets Expansion at CGE");
    assert_eq!(budget(500_000_000_000_000), 3_600_000_000_000, "Expansion meets Maturity at CEM");
    // The five named profiles are admissible; a divisor under the
    // kernel's is not.
    for p in [Profile::REFERENCE, Profile::SLOW_POT, Profile::LONG_WINDOW, Profile::SLOW_AND_LONG, Profile::USAGE_PACED] {
        assert!(p.ok());
    }
    assert!(!Profile { potdiv: 299, window: 522, floor: 1000 }.ok());
    // The reference profile's gate is fully open at any usage.
    assert_eq!(gated_pot(&Profile::REFERENCE, 300_000_000_000_000, 0), poe_kernel::pot(300_000_000_000_000));
    // Usage-paced: at zero usage the gate sits at its floor of a tenth.
    assert_eq!(gate(&Profile::USAGE_PACED, 0), 100);
    assert_eq!(gate(&Profile::USAGE_PACED, 1000), 1000);
}

#[test]
fn a_close_on_the_real_ledger() {
    let mut engine = EpochEngine::new(Profile::REFERENCE, Launch::FairV1);
    let mut l = Ledger::genesis();
    for m in 1..=3u64 {
        l = engine.apply(&l, &Op::Join { machine: m, operator: m * 10, note: note(m * 100, m * 100 + 1, 1, 0) });
    }
    assert_eq!(l.machines.len(), 3);
    let minted_before = l.minted;
    let rep = engine.close(&mut l, 1000, &[]);
    // Genesis economy: ceiling 100,000 binds (budget share and pot share
    // are both larger), three claimants.
    assert_eq!(rep.claimants, 3);
    assert_eq!(rep.grant_each, 100_000);
    assert_eq!(rep.minted_this_close, 300_000);
    assert_eq!(l.minted - minted_before, 300_000, "engine and kernel must agree");
    assert_eq!(l.now, 1);
    // Vesting starts empty and unlocks over credited epochs.
    assert_eq!(engine.vested_balance(1), 0);
    for _ in 0..25 {
        engine.close(&mut l, 1000, &[1, 2, 3]);
    }
    assert_eq!(engine.vested_balance(1), 50_000, "25 credited epochs vest half");
    for _ in 0..25 {
        engine.close(&mut l, 1000, &[1, 2, 3]);
    }
    assert_eq!(engine.vested_balance(1), 100_000, "50 credited epochs vest all");
}

#[test]
fn first_year_envelope_under_a_join_flood() {
    // 400 machines register in epoch 0 and renew every epoch after; the
    // year's grants are bounded by the Genesis budget line the whole way.
    let mut engine = EpochEngine::new(Profile::REFERENCE, Launch::FairV1);
    let mut l = Ledger::genesis();
    let machines: Vec<u64> = (1..=400).collect();
    let mut mark = 1_000_000u64;
    for &m in &machines {
        mark += 2;
        l = engine.apply(&l, &Op::Join { machine: m, operator: m, note: note(mark, mark + 1, 1, 0) });
    }
    assert_eq!(l.machines.len(), 400);
    let mut year_total: u128 = 0;
    for epoch in 0..52u64 {
        let m_at_start = l.minted.saturating_sub(RESERVE);
        let rep = engine.close(&mut l, 1000, &machines);
        assert!(
            rep.minted_this_close <= budget(m_at_start),
            "epoch {epoch} minted {} over budget {}",
            rep.minted_this_close,
            budget(m_at_start)
        );
        year_total += rep.minted_this_close;
        // Everyone renews for the next epoch.
        for &m in &machines {
            mark += 2;
            l = engine.apply(&l, &Op::Renew { machine: m, operator: m, note: note(mark, mark + 1, 1, epoch + 1) });
        }
    }
    assert!(year_total > 0);
    assert!(
        year_total <= 520_200_000_000,
        "first-year grants {year_total} exceed the proved envelope"
    );
}

#[test]
fn renewal_needs_a_full_faithful_term_and_a_kept_bond() {
    let good = FaithfulEpoch { heartbeat_credited: true, storage_answered: true, evidence_named: false };
    let term = vec![good; 25];
    assert!(renewal_eligible(&term, 500, 1000), "exactly half bonded is enough");
    assert!(!renewal_eligible(&term, 499, 1000), "one unit under half is not");
    assert!(!renewal_eligible(&term[..24], 500, 1000), "24 epochs is not a term");
    let mut one_bad = term.clone();
    one_bad[7].storage_answered = false;
    assert!(!renewal_eligible(&one_bad, 500, 1000), "a missed storage answer breaks the term");
    let mut one_evidence = term.clone();
    one_evidence[3].evidence_named = true;
    assert!(!renewal_eligible(&one_evidence, 500, 1000), "evidence breaks the term");

    // The storage challenge is the epoch's state root, on record.
    let roots = vec![(3u64, [9u8; 64]), (4u64, [8u8; 64])];
    assert!(storage_answer_ok(&roots, 3, &[9u8; 64]));
    assert!(!storage_answer_ok(&roots, 3, &[8u8; 64]));
    assert!(!storage_answer_ok(&roots, 5, &[9u8; 64]));
}

#[test]
fn reserve_burns_at_523_only_in_v1() {
    let v1 = EpochEngine::new(Profile::REFERENCE, Launch::FairV1);
    assert!(!v1.reserve_burned(522));
    assert!(v1.reserve_burned(523));
    let v2 = EpochEngine::new(Profile::REFERENCE, Launch::ListedV2);
    assert!(!v2.reserve_burned(523), "the listed launch sells its reserve instead");
}

/// Aggregate replay of the close law over scalars (the Fortran twin's
/// own method: worlds as counts, not per-note ledgers), under the twin's
/// stated reference world: logistic adoption from one million machines
/// to 8·10^9 (r = 0.55/yr), every active machine a miner renewing once a
/// term (so an epoch's claimants are the week's joins plus a term's
/// worth of renewals, active/25), 1.5%/yr of holders' coin lost.
/// Asserts the parameter-free laws (the first-year envelope; supply
/// under the cap) and prints the curve against the twin's band.
#[test]
fn aggregate_replay_forty_years() {
    let profile = Profile::REFERENCE;
    let logistic = |epoch: u64| -> f64 {
        let t = epoch as f64 / 52.0; // years
        8.0e9 / (1.0 + 7999.0 * (-0.55 * t).exp())
    };
    let mut minted_total: u128 = RESERVE; // M + reserve
    let mut live: u128 = RESERVE;
    let mut year1: u128 = 0;
    let (mut c1, mut c10, mut c40) = (0u128, 0u128, 0u128);
    let mut prev_machines = logistic(0);
    for epoch in 0..(52u64 * 40) {
        let machines = logistic(epoch + 1);
        let joins = (machines - prev_machines).max(0.0) as u64;
        prev_machines = machines;
        let claimants = joins + (machines as u64) / 25;
        let grants_to_date = minted_total - RESERVE;
        let economy = if epoch < 523 { live.saturating_sub(RESERVE) } else { live };
        let g = p_grant(&profile, live, economy, grants_to_date, claimants, 1000) as u128;
        let minted = claimants as u128 * g;
        minted_total += minted;
        live += minted;
        // Losses: 1.5%/yr of the non-reserve live coin.
        let non_reserve = live.saturating_sub(if epoch < 523 { RESERVE } else { 0 });
        live -= non_reserve * 15 / 52_000;
        if epoch < 52 {
            year1 += minted;
        }
        let circulation = live.saturating_sub(if epoch < 523 { RESERVE } else { 0 });
        if epoch == 51 {
            c1 = circulation;
        } else if epoch == 519 {
            c10 = circulation;
        } else if epoch == 52 * 40 - 1 {
            c40 = circulation;
        }
    }
    assert!(year1 <= 520_200_000_000, "year 1 minted {year1}");
    // Live supply stays under the cap: every epoch's grants are drawn
    // from the headroom itself (pot and ceiling), losses or not. (The
    // kernel's cumulative-minted bound is a ledger-level invariant,
    // proved in Lean and exercised on real ledgers in the batteries
    // above; this aggregate model's external losses recycle headroom
    // the way the twin's window burns do.)
    assert!(live <= SMAX, "live supply never passes the cap");
    println!(
        "circulation: yr1 {:.3}% · yr10 {:.1}% · yr40 {:.1}% of cap (twin band: 0.039% → 11.8% → 93%)",
        c1 as f64 / SMAX as f64 * 100.0,
        c10 as f64 / SMAX as f64 * 100.0,
        c40 as f64 / SMAX as f64 * 100.0
    );
    assert!(c40 > c10 && c10 > c1, "circulation grows across the decades");
}
