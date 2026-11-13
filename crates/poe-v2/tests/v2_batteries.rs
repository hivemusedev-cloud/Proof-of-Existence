//! Step 10 batteries: the module's own numbers, the pool law, the
//! oracle, the lanes' rules, bridge conservation — and the adversarial
//! trader battery, a deterministic stream of rule-seeking offers in the
//! twin's shape, with invariants checked after every acceptance.

use poe_crypto::hash::{h_u64, Part};
use poe_kernel::{GMAX, RESERVE};
use poe_v2::*;

#[test]
fn the_modules_own_numbers() {
    assert_eq!(P0 * RESERVE, YV, "the virtual ether is the reserve at the genesis price");
    assert_eq!(V / P0, GMAX as u128, "the value bound at the genesis price is the grant ceiling");
    assert_eq!(PC + PL, RESERVE, "the two tranches are the reserve");
    assert_eq!(6 * PL, RESERVE);
    assert_eq!(YV2, P0 * PC);
    assert_eq!(100 * LRATE, PL, "the lane needs a hundred epochs at least");
    assert_eq!(allowance(0), QS);
    for m in [0u128, 7, 1_000_000, 500_000_000_000] {
        assert!(curve_allow(m) + list_allow(m) <= allowance(m));
        assert!(allowance(m + 7) >= allowance(m), "the allowance grows with grants");
    }
    // The oracle's cap at genesis prices is exactly the kernel ceiling.
    assert_eq!(vcap(&[P0, P0, P0]), GMAX as u128);
    assert_eq!(coin_cap(&[]), GMAX as u128);
}

#[test]
fn genesis_pool_law() {
    let mut pool = GPool::genesis();
    assert!(pool_ok(&pool.curve));
    assert_eq!(pool.curve.spot(), P0, "the genesis spot is the genesis price");

    // A buy: coins leave, the product invariant holds, spot never < P0.
    assert!(pool.step(&PoolAct::Buy(1_000_000_000_000_000_000))); // 1 ETH
    assert!(pool_ok(&pool.curve));
    assert!(pool.curve.spot() >= P0);
    assert!(pool.curve.tokens < RESERVE);

    // A block's buys are order-free.
    let base = genesis_curve();
    let ab = batch_pool(&base.pool(), &[100, 250, 50]);
    let ba = batch_pool(&base.pool(), &[50, 250, 100]);
    assert_eq!(ab, ba, "the batch clears to one record whatever the order");

    // A sale that would take the pool past the reserve is refused whole.
    let mut p2 = GPool::genesis();
    let held = p2.curve.tokens;
    assert!(!p2.step(&PoolAct::Sell(1)), "pool already holds the whole reserve");
    assert_eq!(p2.curve.tokens, held);
    // After buys make room, the same sale clears and pays only real wei.
    assert!(p2.step(&PoolAct::Buy(10_000_000_000_000_000_000)));
    let coins_before = p2.curve.coins;
    assert!(p2.step(&PoolAct::Sell(1_000_000)));
    assert!(p2.curve.coins <= coins_before);

    // Retirement: buys stop, returns count burned, nothing is held.
    let mut p3 = GPool::genesis();
    assert!(p3.step(&PoolAct::Buy(5_000_000_000_000_000_000)));
    p3.retire();
    assert_eq!(p3.held(), 0);
    assert!(!p3.step(&PoolAct::Buy(1)), "a retired pool sells nothing more");
    let burned_before = p3.burned;
    assert!(p3.step(&PoolAct::Sell(1000)), "buybacks continue");
    assert_eq!(p3.burned, burned_before + 1000, "and count burned");
}

#[test]
fn oracle_reads_the_highest_of_eight_weeks() {
    let mut hist: Vec<u128> = vec![P0; 8];
    assert_eq!(pcap(&hist), P0);
    hist.push(P0 * 3);
    assert_eq!(pcap(&hist), P0 * 3, "the highest recent week sets the cap price");
    assert_eq!(vcap(&hist), V / (P0 * 3));
    // Eight weeks later the spike is out of the window.
    for _ in 0..8 {
        hist.push(P0);
    }
    assert_eq!(pcap(&hist), P0);
    assert_eq!(weekly_mean(&[10, 20, 60]), 30);
    assert_eq!(weekly_mean(&[]), 0);
}

#[test]
fn listing_lane_rules() {
    let means = vec![P0; 4];
    let mut launch = ListedLaunch::genesis();
    // Before the cliff: refused, whatever the price.
    assert_eq!(launch.listing_sell(1000, P0 * 2, 25, &means, 0), Err(LaneError::BeforeCliff));
    // At the cliff: within allowance (list_allow(0) = 10^12/6) it clears.
    let allow0 = list_allow(0);
    launch.listing_sell(allow0, P0, CLIFF, &means, 0).expect("the lane's first sale");
    // The allowance, not the rate, binds first at zero grants.
    assert_eq!(
        launch.listing_sell(1, P0, CLIFF, &means, 0),
        Err(LaneError::OverAllowance),
        "one coin past the allowance is refused"
    );
    // Below the oracle price: refused even with allowance to spare
    // (grants grown so the allowance no longer binds).
    let mut launch2 = ListedLaunch::genesis();
    let big_m = 14_000_000_000_000u128;
    assert_eq!(
        launch2.listing_sell(1000, P0 - 1, CLIFF, &means, big_m),
        Err(LaneError::PriceTooLow)
    );
    // Over the per-epoch rate: refused; the next epoch has a fresh rate.
    assert_eq!(
        launch2.listing_sell(LRATE + 1, P0, CLIFF, &means, big_m),
        Err(LaneError::OverRate)
    );
    launch2.listing_sell(LRATE, P0, CLIFF, &means, big_m).unwrap();
    launch2.listing_sell(LRATE, P0, CLIFF + 1, &means, big_m).unwrap();
}

#[test]
fn curve_lane_shares_the_allowance() {
    let mut launch = ListedLaunch::genesis();
    // At zero grants the curve may release at most curve_allow(0).
    let want = curve_allow(0);
    // Find a buy by bisection-ish probing: the full-release buy pays
    // YV2-priced coins; instead assert the boundary property directly:
    // a buy whose output is exactly the allowance clears...
    let mut lo = 0u128; // wei
    let mut hi = YV2; // surely past
    while lo + 1 < hi {
        let mid = (lo + hi) / 2;
        if launch.curve.buy_out(mid) <= want {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    let out = launch.curve_buy(lo, 0).expect("at the allowance it clears");
    assert!(out <= want);
    assert_eq!(launch.curve_released_net(), out);
    // ...and any buy big enough to release one more coin is refused
    // (a 1-wei dust buy releases nothing and is not over the allowance —
    // the boundary is on release, not on wei in).
    assert_eq!(launch.curve_buy(YV2, 0), Err(LaneError::OverAllowance));
    // A sale returns coins and frees allowance again.
    let back = launch.curve_sell(out / 2).unwrap();
    assert!(back > 0);
    assert_eq!(launch.curve_released_net(), out - out / 2);
    assert!(launch.curve_buy(lo / 4, 0).is_ok(), "the freed allowance can be spent again");
}

#[test]
fn bridge_fee_and_conservation() {
    // The fee: 1% rounded up, at least 1, at most the cap and the amount.
    assert_eq!(fee_of(u128::MAX, 0), 0);
    assert_eq!(fee_of(u128::MAX, 50), 1);
    assert_eq!(fee_of(u128::MAX, 101), 2);
    assert_eq!(fee_of(3, 1000), 3, "the cap binds");
    assert_eq!(fee_of(u128::MAX, 7), 1, "the amount binds below the floor");
    for a in [0u128, 1, 99, 100, 10_000, 1_000_000_000] {
        assert!(fee_of(1000, a) <= a && fee_of(1000, a) <= 1000);
    }

    let mut lane = BridgeLane::default();
    // No floor and no stock: the quota is zero, nothing drains.
    assert_eq!(lane.deposit(1, 1000, 0, 0), None);
    // With the coin floor, deposits land and wrap; escrow covers wrapped.
    let got = lane.deposit(10_000, 1000, 0, QPOE).unwrap();
    assert_eq!(got, 9_900);
    assert!(lane.conserved());
    // Withdraw part: escrow still covers the rest.
    let back = lane.withdraw(4_000, 1000, 0, QPOE).unwrap();
    assert_eq!(back, 3_960);
    assert!(lane.conserved());
    // More wrapped than exists: refused.
    assert_eq!(lane.withdraw(999_999, 1000, 0, QPOE), None);
    assert!(lane.conserved());
}

/// THE ADVERSARIAL-TRADER BATTERY: 20,000 deterministic offers across
/// every lane — buys sized from dust to absurdity, sales past holdings,
/// listing sales before the cliff / below the oracle / past the rate /
/// past the allowance, bridge moves past quota and stock. Refusals are
/// counted by class (the twin's run refused 15,340 of its stream); every
/// acceptance is followed by the invariant checks.
#[test]
fn adversarial_trader_battery() {
    let mut pool = GPool::genesis();
    let mut launch = ListedLaunch::genesis();
    let mut lane = BridgeLane::default();
    let means = vec![P0; 8];
    let mut grants: u128 = 0;
    let (mut offered, mut refused) = (0u64, 0u64);
    let mut by_class: std::collections::HashMap<&'static str, u64> = Default::default();
    let mut bump = |class: &'static str, by: &mut std::collections::HashMap<&'static str, u64>| {
        *by.entry(class).or_insert(0) += 1;
    };

    for i in 0..20_000u64 {
        let r = h_u64("adversary", &[Part::Nat(i)]);
        offered += 1;
        match i % 5 {
            0 => {
                // Genesis-pool buy or sell, amount across 30 orders of
                // magnitude — sells past the reserve headroom refuse.
                let amt = (r % 1_000_000) as u128 * 10u128.pow((r % 25) as u32);
                let ok = if r % 2 == 0 {
                    pool.step(&PoolAct::Buy(amt))
                } else {
                    pool.step(&PoolAct::Sell((r % 1_000_000) as u128 * 1_000_000_000))
                };
                if ok {
                    assert!(pool_ok(&pool.curve), "pool invariant after trade {i}");
                } else {
                    refused += 1;
                    bump("pool", &mut by_class);
                }
            }
            1 => {
                // Curve-lane buy: most are far past the allowance.
                let amt = (r % 1_000) as u128 * 10u128.pow((r % 28) as u32);
                match launch.curve_buy(amt, grants) {
                    Ok(_) => {
                        assert!(launch.curve_released_net() <= curve_allow(grants));
                        assert!(launch.curve.tokens <= PC);
                    }
                    Err(_) => {
                        refused += 1;
                        bump("curve-allowance", &mut by_class);
                    }
                }
            }
            2 => {
                // Listing sale: random epoch (half before the cliff),
                // price around the floor, amount around the rate.
                let epoch = (r % 60) as u64;
                let price = P0 * (r % 3) as u128;
                let amt = (r % (2 * LRATE as u64)) as u128;
                match launch.listing_sell(amt, price, epoch, &means, grants) {
                    Ok(()) => {
                        assert!(epoch >= CLIFF && price >= P0);
                        assert!(launch.listing_sold_total <= PL);
                    }
                    Err(_) => {
                        refused += 1;
                        bump("listing", &mut by_class);
                    }
                }
            }
            3 => {
                // Bridge moves past quota and stock refuse.
                let amt = (r % 1_000_000) as u128 * 1_000_000_000_000;
                let epoch = (i / 100) as u64;
                let ok = if r % 2 == 0 {
                    lane.deposit(amt, coin_cap(&means), epoch, QPOE).is_some()
                } else {
                    lane.withdraw(amt, coin_cap(&means), epoch, QPOE).is_some()
                };
                assert!(lane.conserved(), "lane conservation after offer {i}");
                if !ok {
                    refused += 1;
                    bump("bridge", &mut by_class);
                }
            }
            _ => {
                // Grants grow slowly through the run (the allowance with
                // them), and the pool takes a block batch now and then.
                grants += (r % 1_000_000) as u128;
                let ds: Vec<u128> = (0..4).map(|k| ((r >> k) % 10_000) as u128).collect();
                let before = pool.curve;
                assert!(pool.step(&PoolAct::Buys(ds)));
                assert!(pool_ok(&pool.curve));
                assert!(pool.curve.tokens <= before.tokens);
            }
        }
    }
    println!("adversarial battery: {offered} offers, {refused} refused, by class: {by_class:?}");
    assert!(refused > offered / 4, "a healthy share of adversarial offers must be refused");
    assert!(by_class.len() >= 4, "refusals land in every lane class");
}
