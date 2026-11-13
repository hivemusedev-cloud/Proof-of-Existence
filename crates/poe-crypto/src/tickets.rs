//! Hash-chain proposal tickets.
//!
//! A machine builds a chain by iterating `H` from a secret seed and commits
//! the tip (the last link) in advance. In each round it reveals one link,
//! walking back toward the seed; anyone can hash the revealed link forward
//! to the committed tip to check it, and no one can predict a future link
//! from the revealed ones. A reveal's ticket is `H("ticket", beacon, link)`,
//! and it wins its round when it falls below `16/A` of its range — at `A`
//! active machines, ~16 expected proposers per round (the manual's rule).

use crate::hash::{h, h_u64, Part, H512};

fn chain_step(link: &H512) -> H512 {
    h("chain", &[Part::Bytes(link)])
}

/// A committed hash chain. The seed never leaves the machine; links are
/// revealed one per round, from the tip backwards.
pub struct TicketChain {
    links: Vec<H512>,
}

impl TicketChain {
    /// Build a chain of `length` links from a secret seed. The commitment
    /// (the tip) is `links[length - 1]`; there are `length - 1` reveals.
    pub fn new(seed: &[u8], length: usize) -> TicketChain {
        assert!(length >= 2, "a chain needs at least a seed link and a tip");
        let mut links = Vec::with_capacity(length);
        links.push(h("chain-seed", &[Part::Bytes(seed)]));
        for i in 1..length {
            links.push(chain_step(&links[i - 1]));
        }
        TicketChain { links }
    }

    /// The commitment published in advance: the chain tip.
    pub fn commitment(&self) -> H512 {
        *self.links.last().expect("length >= 2")
    }

    /// The link to reveal at step `step` (1-based: step 1 is the first
    /// round after commitment). Panics out of range, like a mis-set clock.
    pub fn reveal(&self, step: usize) -> H512 {
        assert!(step >= 1 && step < self.links.len(), "reveal step out of range");
        self.links[self.links.len() - 1 - step]
    }
}

/// Verify a reveal: hashing `link` forward `step` times must reach the
/// committed tip.
pub fn verify_reveal(commitment: &H512, step: usize, link: &H512) -> bool {
    let mut acc = *link;
    for _ in 0..step {
        acc = chain_step(&acc);
    }
    &acc == commitment
}

/// A reveal's ticket score under a round beacon, read as a 64-bit number.
pub fn ticket_score(beacon: &[u8], link: &H512) -> u64 {
    h_u64("ticket", &[Part::Bytes(beacon), Part::Bytes(link)])
}

/// The win rule: the score falls below `16/A` of the `2^64` range. With no
/// active machines there are no winners; with `A <= 16` every ticket wins.
pub fn ticket_wins(score: u64, active: u64) -> bool {
    if active == 0 {
        return false;
    }
    let threshold = (16u128 << 64) / (active as u128);
    (score as u128) < threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_reveals_verify_and_only_in_order() {
        let chain = TicketChain::new(b"machine-7-secret-seed", 64);
        let tip = chain.commitment();
        for step in 1..64 {
            let link = chain.reveal(step);
            assert!(verify_reveal(&tip, step, &link), "step {step}");
            // The same link at any other step does not verify.
            assert!(!verify_reveal(&tip, step % 63 + 1, &link) || step % 63 + 1 == step);
            // A link from another machine's chain does not verify.
            let other = TicketChain::new(b"machine-8-secret-seed", 64);
            assert!(!verify_reveal(&tip, step, &other.reveal(step)));
        }
    }

    #[test]
    fn threshold_boundary_is_exact() {
        // H("ticket", b"beacon", 42) begins a37ecf26... — its score sits at
        // ~0.6393 of the range: wins at A = 25 (16/25 = 0.64), loses at 26.
        let score = h_u64("ticket", &[Part::Bytes(b"beacon"), Part::Nat(42)]);
        assert!(ticket_wins(score, 25));
        assert!(!ticket_wins(score, 26));
        assert!(ticket_wins(score, 16), "A <= 16: everyone proposes");
        assert!(ticket_wins(0, 1_000_000));
        assert!(!ticket_wins(u64::MAX, 1_000_000));
        assert!(!ticket_wins(0, 0), "no active machines, no winners");
    }

    #[test]
    fn expected_proposers_near_sixteen() {
        // Deterministic census: 4,000 reveals at A = 200 (win rate 16/200)
        // must land near 320 winners — loose bounds, this checks the scale
        // of the threshold, not luck.
        let chain = TicketChain::new(b"census-seed", 4001);
        let beacon = b"round-beacon-1";
        let mut winners = 0u32;
        for step in 1..=4000 {
            if ticket_wins(ticket_score(beacon, &chain.reveal(step)), 200) {
                winners += 1;
            }
        }
        assert!((240..=400).contains(&winners), "winners = {winners}, expected ~320");
    }
}
