//! Step 8 batteries: the container round-trip and tamper check, the
//! offline double-spend drill (the finish line), merchant policy,
//! vouchers, and the splitting bounds.

use poe_wallet::*;

fn a_container() -> Container {
    Container {
        coin: 4242,
        nf: 4243,
        asset: 0,
        value: 750,
        born: 12,
        owner: 7,
        line: LineKey { secret: 123_456_789, blind: 987_654_321 },
        shows: vec![],
    }
}

#[test]
fn container_is_exactly_one_kib_and_round_trips() {
    let mut c = a_container();
    let bytes = c.to_bytes();
    assert_eq!(bytes.len(), 1024);
    assert_eq!(Container::from_bytes(&bytes).unwrap(), c);

    // The show log round-trips too.
    let s = show(&c.line, c.coin, 555);
    c.record_show(&s, 88).unwrap();
    let bytes2 = c.to_bytes();
    let back = Container::from_bytes(&bytes2).unwrap();
    assert_eq!(back, c);
    assert_eq!(back.shows.len(), 1);

    // Any tamper breaks the checksum; a short buffer is not a container.
    let mut bad = bytes;
    bad[100] ^= 1;
    assert!(Container::from_bytes(&bad).is_err());
    assert!(Container::from_bytes(&bytes[..512]).is_err());
    // Recording the same challenge twice is refused by the wallet itself.
    assert!(c.record_show(&s, 89).is_err());
}

/// THE OFFLINE DOUBLE-SPEND DRILL: one coin, shown offline on two
/// branches; at merge the two shows extract the line secret and unmask
/// the spender. An honest single show reveals nothing.
#[test]
fn offline_double_spend_drill() {
    let c = a_container();
    let owner_commitment = c.line.commitment();

    // Branch 1: merchant A, offline, challenge from A's context.
    let policy = MerchantPolicy { per_coin_limit: 1000, per_customer_limit: 5000, bond: None };
    let show_a = show(&c.line, c.coin, 111_222);
    policy.accept(c.value, c.value, 0).expect("within policy — accepted offline");

    // Branch 2: the same coin shown to merchant B at B's challenge. The
    // double-spend itself, offline and undetectable — until merge.
    let show_b = show(&c.line, c.coin, 999_000);
    policy.accept(c.value, c.value, 0).expect("also within policy — that is the offline risk, bounded by policy");

    // MERGE: the two shows name the secret, and the secret names the
    // owner who committed to it at the coin's creation.
    let secret = extract_secret(&show_a, &show_b).expect("two shows must extract");
    assert_eq!(secret, c.line.secret);
    let unmasked = LineKey { secret, blind: c.line.blind };
    assert_eq!(unmasked.commitment(), owner_commitment, "the extracted secret is the committed owner's");

    // Same challenge twice extracts nothing (a replay, not a double-show).
    let replay = show(&c.line, c.coin, 111_222);
    assert_eq!(extract_secret(&show_a, &replay), None);
    // And a different coin's shows don't mix.
    let other = show(&c.line, 7777, 5);
    assert_eq!(extract_secret(&show_a, &other), None);

    // The honest single show: for ANY candidate secret there is a blind
    // that satisfies the same show — one equation, two unknowns; the
    // show alone carries no information about the secret.
    for fake_secret in [0u64, 1, 42, 999_999_999] {
        // blind' = r − c·s' always exists in the field:
        let blind_fake = {
            let p = LINE_P as u128;
            let r = show_a.response as u128;
            let cs = (show_a.challenge as u128 * fake_secret as u128) % p;
            ((r + p - cs) % p) as u64
        };
        assert!(show_consistent(fake_secret, blind_fake, &show_a));
    }
    assert!(show_consistent(c.line.secret, c.line.blind, &show_a));
}

#[test]
fn merchant_policy_bounds() {
    let p = MerchantPolicy { per_coin_limit: 100, per_customer_limit: 250, bond: Some(50) };
    assert_eq!(p.accept(101, 101, 50), Err(PolicyError::CoinTooLarge));
    assert_eq!(p.accept(100, 251, 50), Err(PolicyError::CustomerOverLimit));
    assert_eq!(p.accept(100, 250, 49), Err(PolicyError::BondMissing));
    assert_eq!(p.accept(100, 250, 50), Ok(()));
    let no_bond = MerchantPolicy { bond: None, ..p };
    assert_eq!(no_bond.accept(100, 250, 0), Ok(()));
}

#[test]
fn vouchers_redeem_once() {
    let mut book = VoucherBook::default();
    let v = Voucher::issue(3, 9, 17, 1);
    assert!(book.redeem(&v));
    assert!(!book.redeem(&v), "a voucher is a one-time claim");
    let v2 = Voucher::issue(3, 9, 17, 2);
    assert_ne!(v.id, v2.id);
    assert!(book.redeem(&v2));
}

#[test]
fn splitting_bounds() {
    for amount in [0u64, 1, 7, 99, 999_999] {
        let bills = split_125(amount);
        assert_eq!(bills.iter().sum::<u64>(), amount);
        assert!(bills.len() <= 18, "{amount} took {} bills", bills.len());
        for b in &bills {
            let d = b.to_string();
            assert!(d.starts_with(['1', '2', '5']), "{b} is not a 1-2-5 bill");
        }
    }
    // Grant-size amounts (< 10^9): at most 27 bills.
    for amount in [400_000_000u64, 999_999_999, 123_456_789] {
        let bills = split_125(amount);
        assert_eq!(bills.iter().sum::<u64>(), amount);
        assert!(bills.len() <= 27, "{amount} took {} bills", bills.len());
    }
    assert_eq!(split_125(0), Vec::<u64>::new());
    assert_eq!(split_125(7), vec![5, 2]);
}
