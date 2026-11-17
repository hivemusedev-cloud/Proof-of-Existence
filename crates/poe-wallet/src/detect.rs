//! Detection tags — how a wallet finds its incoming notes and
//! messages without scanning or opening everyone's (Manual
//! line 199 and §10/§12; light-duty design note §5).
//!
//! The Manual's definition (Part M) is exact:
//!
//! ```text
//! TAG_DET = 6,  TAGSPAN = 2^384
//! detTag(k, i, e) = e · TAGSPAN + (H [TAG_DET, k, i, e] mod TAGSPAN)
//! tagEpoch(t)     = t / TAGSPAN
//! ```
//!
//! A tag is its **epoch in clear above 384 bits of hash** of
//! the pairwise secret `k`, the per-pair counter `i` and the
//! epoch `e`. The hash part at 384 bits clears 128 against
//! generic quantum collision search (Manual line 535). In
//! this crate's concrete hash the domain constant TAG_DET is
//! the `"det"` domain string, as with the codebase's other
//! domains; `k` enters as its 32 bytes.
//!
//! Who uses it (Manual line 451): after a first contact,
//! payer and payee hold a pairwise secret; every payment and
//! every message carries the tag for its counter and epoch.
//! The payee computes its expected tags — per contact, per
//! epoch since it last looked — and matches them against the
//! tag stream. Distinct (k, i, e) give distinct tags where
//! the hash separates (`tags_are_unique`), so an honest
//! arrival is never missed or taken for another's.
//!
//! A first payment is found the same way: an **invoice
//! carries a one-time tag seed**, and the first payment's tag
//! is the seed's tag at counter 0 ([`invoice_tag`]). A first
//! contact with *no* invoice falls back to trial
//! decapsulation — one ML-KEM decapsulation per new output,
//! batched on the phone or handed to a detection service
//! (Manual line 451). That fallback belongs to the address
//! layer (ML-KEM encapsulation keys), which is not built in
//! this stack yet; what is built here is the tag itself and
//! the payee-side scan, which is the part every arrival
//! after first contact uses.
//!
//! The scan is the batched method the design note names:
//! the expected set is computed once per scan and held in a
//! hash set, so each candidate in the stream costs one set
//! lookup — not one decapsulation. The scanner tracks each
//! contact's next counter; a match at counter `i` advances
//! the contact past `i`, so a settled tag is never expected
//! again (a replayed tag matches nothing the second time).

use poe_crypto::hash::{h, Part};
use std::collections::{BTreeMap, HashMap, HashSet};

/// The hash part of a tag: 384 bits (TAGSPAN = 2^384).
pub const TAG_HASH_BYTES: usize = 48;
/// A tag on the wire: 8-byte big-endian epoch + the hash part.
pub const TAG_BYTES: usize = 8 + TAG_HASH_BYTES;

/// A detection tag: the epoch in clear, the hash below it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DetectionTag {
    pub epoch: u64,
    pub hash: [u8; TAG_HASH_BYTES],
}

/// The detection tag of counter `counter` under pairwise
/// secret `secret`, sent in `epoch` — the Manual's `detTag`.
pub fn det_tag(secret: &[u8; 32], counter: u64, epoch: u64) -> DetectionTag {
    let full = h(
        "det",
        &[Part::Bytes(secret), Part::Nat(counter), Part::Nat(epoch)],
    );
    let mut hash = [0u8; TAG_HASH_BYTES];
    hash.copy_from_slice(&full[..TAG_HASH_BYTES]);
    DetectionTag { epoch, hash }
}

/// The tag a first payment carries under an invoice's
/// one-time tag seed: the seed's tag at counter 0, found by
/// the same scan as any later arrival.
pub fn invoice_tag(seed: &[u8; 32], epoch: u64) -> DetectionTag {
    det_tag(seed, 0, epoch)
}

impl DetectionTag {
    /// The epoch this tag names (`tagEpoch`).
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn to_bytes(&self) -> [u8; TAG_BYTES] {
        let mut out = [0u8; TAG_BYTES];
        out[..8].copy_from_slice(&self.epoch.to_be_bytes());
        out[8..].copy_from_slice(&self.hash);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<DetectionTag> {
        if bytes.len() != TAG_BYTES {
            return None;
        }
        let mut epoch = [0u8; 8];
        epoch.copy_from_slice(&bytes[..8]);
        let mut hash = [0u8; TAG_HASH_BYTES];
        hash.copy_from_slice(&bytes[8..]);
        Some(DetectionTag { epoch: u64::from_be_bytes(epoch), hash })
    }
}

/// One matched arrival: which contact, at which counter and
/// epoch. The tag itself is the record's height in the
/// message registry's sense; the payload is fetched by it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionMatch {
    pub contact: String,
    pub counter: u64,
    pub epoch: u64,
    pub tag: DetectionTag,
}

/// The payee side: per-contact pairwise secrets and the next
/// counter expected from each. State the wallet keeps beside
/// its sessions (design note §5); the secrets never leave it
/// through this API (add-only).
#[derive(Debug, Default)]
pub struct Scanner {
    contacts: BTreeMap<String, Contact>,
}

#[derive(Debug)]
struct Contact {
    secret: [u8; 32],
    next_counter: u64,
}

impl Scanner {
    pub fn new() -> Scanner {
        Scanner::default()
    }

    /// Establish (or replace) a contact's pairwise secret.
    /// Replacing resets the expected counter to 0 — a new
    /// secret is a new pairing.
    pub fn add_contact(&mut self, name: &str, secret: [u8; 32]) {
        self.contacts.insert(name.to_string(), Contact { secret, next_counter: 0 });
    }

    pub fn remove_contact(&mut self, name: &str) -> bool {
        self.contacts.remove(name).is_some()
    }

    pub fn contacts(&self) -> Vec<String> {
        self.contacts.keys().cloned().collect()
    }

    pub fn next_counter(&self, name: &str) -> Option<u64> {
        self.contacts.get(name).map(|c| c.next_counter)
    }

    /// Serialize the book (contacts in name order) for custody
    /// storage: u32 count, then per contact a u16 name
    /// length, the name, the 32-byte secret and the u64 next
    /// counter. The bytes are secret material — they belong
    /// inside the wallet's encrypted store, never in plain
    /// files.
    pub fn export_state(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.contacts.len() as u32).to_be_bytes());
        for (name, c) in &self.contacts {
            out.extend_from_slice(&(name.len() as u16).to_be_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&c.secret);
            out.extend_from_slice(&c.next_counter.to_be_bytes());
        }
        out
    }

    /// Restore a book from [`Scanner::export_state`] bytes.
    /// Malformed input is refused whole — never a partial
    /// book.
    pub fn import_state<'a>(bytes: &'a [u8]) -> Option<Scanner> {
        let mut pos = 0usize;
        let take = |bytes: &'a [u8], pos: &mut usize, n: usize| -> Option<&'a [u8]> {
            let s = bytes.get(*pos..*pos + n)?;
            *pos += n;
            Some(s)
        };
        let count = u32::from_be_bytes(take(bytes, &mut pos, 4)?.try_into().ok()?) as usize;
        let mut sc = Scanner::new();
        for _ in 0..count {
            let nl = u16::from_be_bytes(take(bytes, &mut pos, 2)?.try_into().ok()?) as usize;
            let name = String::from_utf8(take(bytes, &mut pos, nl)?.to_vec()).ok()?;
            let secret: [u8; 32] = take(bytes, &mut pos, 32)?.try_into().ok()?;
            let next = u64::from_be_bytes(take(bytes, &mut pos, 8)?.try_into().ok()?);
            sc.contacts.insert(name, Contact { secret, next_counter: next });
        }
        if pos != bytes.len() {
            return None;
        }
        Some(sc)
    }

    /// The expected tags for one contact over an epoch
    /// window: counters `next..next + lookahead` for each
    /// epoch in `epochs`. The sender's counter is sequential
    /// per pair, so a bounded lookahead past the next unseen
    /// counter covers bursts; anything beyond it is found by
    /// the next scan once earlier counters land.
    pub fn expected(
        &self,
        name: &str,
        epochs: &[u64],
        lookahead: u64,
    ) -> Vec<(u64, DetectionTag)> {
        let Some(c) = self.contacts.get(name) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for &e in epochs {
            for i in c.next_counter..c.next_counter.saturating_add(lookahead) {
                out.push((i, det_tag(&c.secret, i, e)));
            }
        }
        out
    }

    /// Scan a candidate tag stream for every contact over
    /// the epoch window. The expected set is built once
    /// (the batch), then each candidate costs one lookup.
    /// Matches advance each contact's next counter past the
    /// matched counter, so the same tag never matches twice.
    /// Candidates outside the window or under no contact are
    /// ignored — they are somebody else's, or another
    /// epoch's, and the scan learns nothing about them.
    pub fn scan(
        &mut self,
        candidates: &[DetectionTag],
        epochs: &[u64],
        lookahead: u64,
    ) -> Vec<DetectionMatch> {
        let mut expected: HashMap<[u8; TAG_HASH_BYTES], (String, u64, u64)> = HashMap::new();
        for (name, c) in &self.contacts {
            for &e in epochs {
                for i in c.next_counter..c.next_counter.saturating_add(lookahead) {
                    let t = det_tag(&c.secret, i, e);
                    expected.insert(t.hash, (name.clone(), i, e));
                }
            }
        }
        let epoch_set: HashSet<u64> = epochs.iter().copied().collect();
        let mut matched_counters: HashMap<String, u64> = HashMap::new();
        let mut out = Vec::new();
        for t in candidates {
            if !epoch_set.contains(&t.epoch) {
                continue;
            }
            if let Some((name, i, e)) = expected.get(&t.hash) {
                if *e == t.epoch {
                    out.push(DetectionMatch {
                        contact: name.clone(),
                        counter: *i,
                        epoch: *e,
                        tag: *t,
                    });
                    let top = matched_counters.entry(name.clone()).or_insert(*i);
                    if *i > *top {
                        *top = *i;
                    }
                }
            }
        }
        for (name, top) in matched_counters {
            if let Some(c) = self.contacts.get_mut(&name) {
                c.next_counter = c.next_counter.max(top.saturating_add(1));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn a_tag_names_its_epoch_and_round_trips() {
        let t = det_tag(&secret(9), 5, 1234);
        assert_eq!(t.epoch(), 1234);
        let bytes = t.to_bytes();
        assert_eq!(bytes.len(), TAG_BYTES);
        assert_eq!(DetectionTag::from_bytes(&bytes), Some(t));
        assert_eq!(DetectionTag::from_bytes(&bytes[..TAG_BYTES - 1]), None);
        // The invoice tag is the seed's counter-0 tag.
        assert_eq!(invoice_tag(&secret(9), 77), det_tag(&secret(9), 0, 77));
    }

    #[test]
    fn distinct_pairs_counters_epochs_give_distinct_tags() {
        // tags_are_unique, sampled: no collisions across a
        // grid of secrets, counters and epochs.
        let mut seen = HashSet::new();
        for s in [1u8, 2, 3] {
            for i in 0..50u64 {
                for e in [0u64, 1, 52] {
                    let t = det_tag(&secret(s), i, e);
                    assert!(seen.insert(t), "collision at secret {s} counter {i} epoch {e}");
                }
            }
        }
        assert_eq!(seen.len(), 3 * 50 * 3);
    }

    #[test]
    fn scan_finds_exactly_the_planted_arrivals() {
        let mut sc = Scanner::new();
        sc.add_contact("alice", secret(0xA1));
        sc.add_contact("bob", secret(0xB0));
        // The stream: noise from strangers, plus arrivals —
        // alice at counters 0,1 (epoch 10) and 2 (epoch 11),
        // bob at counter 0 (epoch 11), one invoice first
        // payment under its seed (epoch 10).
        let mut stream: Vec<DetectionTag> = (0..300u64)
            .map(|n| det_tag(&secret(0x77), n, 10 + (n % 2)))
            .collect();
        stream.push(det_tag(&secret(0xA1), 0, 10));
        stream.push(det_tag(&secret(0xA1), 1, 10));
        stream.push(det_tag(&secret(0xA1), 2, 11));
        stream.push(det_tag(&secret(0xB0), 0, 11));
        stream.push(invoice_tag(&secret(0x1C), 10));
        sc.add_contact("invoice-7", secret(0x1C));

        let found = sc.scan(&stream, &[10, 11], 8);
        let mut got: Vec<(String, u64, u64)> =
            found.iter().map(|m| (m.contact.clone(), m.counter, m.epoch)).collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("alice".to_string(), 0, 10),
                ("alice".to_string(), 1, 10),
                ("alice".to_string(), 2, 11),
                ("bob".to_string(), 0, 11),
                ("invoice-7".to_string(), 0, 10),
            ]
        );
        // Counters advanced past what landed.
        assert_eq!(sc.next_counter("alice"), Some(3));
        assert_eq!(sc.next_counter("bob"), Some(1));
        // A replayed stream matches nothing the second time.
        assert!(sc.scan(&stream, &[10, 11], 8).is_empty());
        // A wrong-secret scanner finds nothing in the stream.
        let mut stranger = Scanner::new();
        stranger.add_contact("mallory", secret(0xEE));
        assert!(stranger.scan(&stream, &[10, 11], 8).is_empty());
        // Outside the epoch window, arrivals are not seen.
        let mut late = Scanner::new();
        late.add_contact("alice", secret(0xA1));
        assert!(late.scan(&stream, &[12], 8).is_empty());
    }

    #[test]
    fn scanner_state_round_trips_through_custody_bytes() {
        let mut sc = Scanner::new();
        sc.add_contact("alice", secret(0xA1));
        sc.add_contact("bob", secret(0xB0));
        let stream = vec![det_tag(&secret(0xA1), 0, 10), det_tag(&secret(0xA1), 1, 10)];
        assert_eq!(sc.scan(&stream, &[10], 8).len(), 2);
        let bytes = sc.export_state();
        let mut back = Scanner::import_state(&bytes).expect("state restores");
        assert_eq!(back.contacts(), vec!["alice".to_string(), "bob".to_string()]);
        assert_eq!(back.next_counter("alice"), Some(2));
        assert_eq!(back.next_counter("bob"), Some(0));
        // The restored book keeps scanning where it left off.
        assert!(back.scan(&stream, &[10], 8).is_empty());
        // Truncated or padded state is refused whole.
        assert!(Scanner::import_state(&bytes[..bytes.len() - 1]).is_none());
        let mut padded = bytes.clone();
        padded.push(0);
        assert!(Scanner::import_state(&padded).is_none());
    }
}
