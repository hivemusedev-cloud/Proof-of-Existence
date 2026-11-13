//! Step 9 batteries: the T25-style replay battery at full scale (100k
//! messages), the window rule, the ratchet (round-trip, out-of-order,
//! deniability), and slot accounting.

use poe_crypto::pq::KemKeypair;
use poe_msg::*;

/// THE T25-STYLE BATTERY: 100,000 distinct messages claim their tags;
/// all 100,000 replays are refused as replays; all 100,000 restamps
/// (same tag, different message) are refused as restamps.
#[test]
fn t25_replay_battery_100k() {
    let shared = [7u8; 64];
    let window = 12u64;
    let mut claims = TagClaims::default();
    let n = 100_000u64;
    for i in 0..n {
        let tag = detection_tag(&shared, window, i);
        assert_eq!(claims.claim(tag, window, 1_000_000 + i, window), ClaimOutcome::Accepted);
    }
    assert_eq!(claims.len(), n as usize);
    let mut replays = 0u64;
    let mut restamps = 0u64;
    for i in 0..n {
        let tag = detection_tag(&shared, window, i);
        match claims.claim(tag, window, 1_000_000 + i, window) {
            ClaimOutcome::Replay => replays += 1,
            other => panic!("expected replay, got {other:?}"),
        }
        match claims.claim(tag, window, 9_999_999 - i, window) {
            ClaimOutcome::Restamp => restamps += 1,
            other => panic!("expected restamp, got {other:?}"),
        }
    }
    assert_eq!(replays, n);
    assert_eq!(restamps, n);
    // A different conversation's tags never collide with these claims:
    // a stranger cannot recognize or squat the tags.
    let stranger = [9u8; 64];
    for i in 0..1000u64 {
        let tag = detection_tag(&stranger, window, i);
        assert_eq!(claims.claim(tag, window, i, window), ClaimOutcome::Accepted);
    }
}

#[test]
fn window_rule() {
    let shared = [3u8; 64];
    let mut claims = TagClaims::default();
    let tag = detection_tag(&shared, 5, 0);
    // Epoch 20 is in window 5; epoch 24 opens window 6 and the old tag's
    // window is gone.
    assert_eq!(window_of(20), 5);
    assert_eq!(window_of(23), 5);
    assert_eq!(window_of(24), 6);
    assert_eq!(claims.claim(tag, 4, 1, 5), ClaimOutcome::WrongWindow, "the past window is closed");
    assert_eq!(claims.claim(tag, 6, 1, 5), ClaimOutcome::WrongWindow, "the future window is not open");
    assert_eq!(claims.claim(tag, 5, 1, 5), ClaimOutcome::Accepted);
}

#[test]
fn ratchet_round_trip_and_out_of_order() {
    let mut rng = rand::thread_rng();
    let responder = KemKeypair::generate(&mut rng);
    let (_ct, mut alice, mut bob) = initiate(&mut rng, &responder);

    let (i0, c0) = alice.encrypt(b"hello bob");
    let (i1, c1) = alice.encrypt(b"second message, delivered late");
    let (i2, c2) = alice.encrypt(b"third");
    assert_eq!(bob.decrypt(i0, &c0).unwrap(), b"hello bob");
    // Out of order: third before second.
    assert_eq!(bob.decrypt(i2, &c2).unwrap(), b"third");
    assert_eq!(bob.decrypt(i1, &c1).unwrap(), b"second message, delivered late");
    // A consumed message's key is gone: no re-decryption.
    assert!(bob.decrypt(i1, &c1).is_none());
    // Garbage under a key decrypts to garbage, not to the plaintext.
    let (i3, c3) = alice.encrypt(b"integrity rides the tag layer");
    let mut tampered = c3.clone();
    tampered[0] ^= 1;
    assert_ne!(bob.decrypt(i3, &tampered).unwrap(), b"integrity rides the tag layer");
    let _ = i3;
    let _ = c3;
}

/// Deniability, by construction: the wire carries no signatures, and
/// everything on it is derivable from the shared secret both parties
/// hold — a transcript "from Alice" is equally producible by Bob. The
/// test shows Bob's own ratchet (started from the same secret) making a
/// ciphertext Alice's side happily decrypts as the next message.
#[test]
fn deniable_by_construction() {
    let shared = [11u8; 64];
    let mut alice = from_shared(&shared);
    let mut bob = from_shared(&shared);
    // Bob fabricates "Alice's" first message;
    let (i, ct) = bob.encrypt(b"meet at noon (fabricated by bob)");
    // Alice's side decrypts it as a genuine incoming message at index 0.
    assert_eq!(alice.decrypt(i, &ct).unwrap(), b"meet at noon (fabricated by bob)");
}

#[test]
fn slots_are_priced_and_spent_once() {
    let mut acct = SlotAccount::default();
    assert_eq!(SlotAccount::allowance(true), 65_536);
    assert_eq!(SlotAccount::allowance(false), 0);
    // An uncredited machine cannot send at all.
    assert!(!acct.spend(1, 7, 0, false));
    // A credited machine spends each slot once, up to the allowance.
    assert!(acct.spend(1, 7, 0, true));
    assert!(!acct.spend(1, 7, 0, true), "the same slot twice is refused");
    assert!(acct.spend(1, 7, 65_535, true), "the last slot");
    assert!(!acct.spend(1, 7, 65_536, true), "past the allowance is refused");
    // Another epoch, another account.
    assert!(acct.spend(1, 8, 0, true));
}
