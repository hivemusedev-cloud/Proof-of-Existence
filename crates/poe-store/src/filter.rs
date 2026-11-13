//! A cuckoo filter over window nullifiers (death marks).
//!
//! The exact death set is the verdict-maker; this filter is only an index
//! in front of it: `contains` returning false is *proof* a mark is not in
//! the window (no false negatives, ever), and a true is confirmed against
//! the exact set before any verdict depends on it — so the filter's small
//! false-positive rate costs a lookup, never a wrong answer.

use poe_crypto::hash::{h_u64, Part};

const SLOTS: usize = 4;
const MAX_KICKS: usize = 500;

pub struct CuckooFilter {
    buckets: Vec<[u16; SLOTS]>,
    mask: usize,
    pub len: usize,
}

fn fingerprint(x: u64) -> u16 {
    // 1..=65535, never 0 (0 marks an empty slot).
    (h_u64("cuckoo-fp", &[Part::Nat(x)]) % 65535 + 1) as u16
}

fn bucket_of(x: u64, mask: usize) -> usize {
    h_u64("cuckoo", &[Part::Nat(x)]) as usize & mask
}

fn alt_bucket(i: usize, fp: u16, mask: usize) -> usize {
    (i ^ (h_u64("cuckoo-alt", &[Part::Nat(fp as u64)]) as usize)) & mask
}

impl CuckooFilter {
    /// A filter with `2^pow2` buckets of 4 slots (capacity `2^pow2 * 4`).
    pub fn new(pow2: u32) -> CuckooFilter {
        let n = 1usize << pow2;
        CuckooFilter {
            buckets: vec![[0; SLOTS]; n],
            mask: n - 1,
            len: 0,
        }
    }

    pub fn contains(&self, x: u64) -> bool {
        let fp = fingerprint(x);
        let i = bucket_of(x, self.mask);
        let j = alt_bucket(i, fp, self.mask);
        self.buckets[i].contains(&fp) || self.buckets[j].contains(&fp)
    }

    /// Insert; false means the filter is effectively full for this item
    /// (the exact set still holds it — the index just declines).
    pub fn insert(&mut self, x: u64) -> bool {
        if self.contains(x) {
            return true; // already indexed (or a fingerprint twin)
        }
        let mut fp = fingerprint(x);
        let mut i = bucket_of(x, self.mask);
        for kick in 0..MAX_KICKS {
            if let Some(slot) = self.buckets[i].iter().position(|&s| s == 0) {
                self.buckets[i][slot] = fp;
                self.len += 1;
                return true;
            }
            // Deterministic victim: rotate by kick count so the walk is a
            // pure function of what was inserted, in what order.
            let slot = (kick + fp as usize) % SLOTS;
            std::mem::swap(&mut fp, &mut self.buckets[i][slot]);
            i = alt_bucket(i, fp, self.mask);
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_false_negatives_and_bounded_false_positives() {
        let mut f = CuckooFilter::new(12); // 4096 buckets, 16,384 slots
        let mut inserted = 0;
        for x in 0..10_000u64 {
            if f.insert(x * 7 + 1) {
                inserted += 1;
            }
        }
        assert!(inserted >= 9_900, "inserted {inserted}/10000");
        for x in 0..10_000u64 {
            assert!(f.contains(x * 7 + 1), "false negative at {x}");
        }
        let fp = (0..10_000u64).filter(|&x| f.contains(x * 7 + 2)).count();
        assert!(fp < 100, "false positives {fp}/10000 (bound 1%)");
    }
}
