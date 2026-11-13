//! poe-wallet — the wallet core and the offline protocol (BUILD_FLOW
//! Step 8).
//!
//! **The Existence Container** is the coin's travelling record: exactly
//! 1 KiB, owner-side, holding the coin's marks, its value and birth, and
//! its **line key** — a secret `s` and a blind `a`. What crosses to a
//! merchant in an offline payment is never the container but a **show**:
//! at the payment's challenge `c` (the merchant's own context hash), the
//! wallet reveals the single field element
//!
//! `r = a + c·s  (mod p)`, p the Goldilocks prime.
//!
//! One show is one equation in two unknowns — for *any* candidate secret
//! there is a blind that satisfies it, so an honest show reveals nothing.
//! Two shows of the same coin at different challenges are two equations:
//! `s = (r₁ − r₂)/(c₁ − c₂)` — the secret falls out, and since the coin's
//! owner committed to `s` at the coin's creation, the double-spender is
//! unmasked when the two offline branches merge. (The show's *binding*
//! to the coin — that this line is this coin's line — is poe-zk's
//! OfflineShowLine proof; this crate is the arithmetic and the record.)
//!
//! Around the show: the **merchant offline policy** (per-coin and
//! per-customer limits, optional bonds — offline acceptance is bounded
//! by policy, detection happens at merge), **slot vouchers** (one-time
//! claims on service slots), and **1-2-5 splitting** (any amount under
//! 10⁶ in at most 18 bills, any grant-size amount in at most 27).

use poe_crypto::hash::{h, Part};

/// The line field: the Goldilocks prime 2^64 − 2^32 + 1.
pub const LINE_P: u64 = 0xFFFF_FFFF_0000_0001;

fn fadd(a: u64, b: u64) -> u64 {
    ((a as u128 + b as u128) % LINE_P as u128) as u64
}
fn fsub(a: u64, b: u64) -> u64 {
    ((a as u128 + LINE_P as u128 - b as u128) % LINE_P as u128) as u64
}
fn fmul(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % LINE_P as u128) as u64
}
fn finv(a: u64) -> Option<u64> {
    if a == 0 {
        return None;
    }
    // Fermat: a^(p−2) mod p.
    let mut acc: u128 = 1;
    let mut base = a as u128;
    let mut e = LINE_P - 2;
    let p = LINE_P as u128;
    while e > 0 {
        if e & 1 == 1 {
            acc = acc * base % p;
        }
        base = base * base % p;
        e >>= 1;
    }
    Some(acc as u64)
}

// -- line keys and shows ------------------------------------------------------

/// A coin's line key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineKey {
    pub secret: u64,
    pub blind: u64,
}

impl LineKey {
    /// The commitment the coin's creation binds the owner to: two shows
    /// extracting this secret unmask exactly this commitment's owner.
    pub fn commitment(&self) -> [u8; 64] {
        h("line-commit", &[Part::Nat(self.secret), Part::Nat(self.blind)])
    }
}

/// One offline show of a coin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Show {
    pub coin: u64,
    pub challenge: u64,
    pub response: u64,
}

/// Show the coin at a challenge: reveal `r = a + c·s`.
pub fn show(line: &LineKey, coin: u64, challenge: u64) -> Show {
    Show {
        coin,
        challenge,
        response: fadd(line.blind, fmul(challenge, line.secret)),
    }
}

/// Does this response satisfy the line equation for a candidate
/// (secret, blind)? — the check that makes a single show meaningless:
/// for any secret there is a blind passing it.
pub fn show_consistent(secret: u64, blind: u64, s: &Show) -> bool {
    s.response == fadd(blind, fmul(s.challenge, secret))
}

/// Extract the line secret from two shows of the same coin at different
/// challenges. This is the double-spend unmasking: it succeeds exactly
/// when the coin was shown twice.
pub fn extract_secret(a: &Show, b: &Show) -> Option<u64> {
    if a.coin != b.coin || a.challenge == b.challenge {
        return None;
    }
    let num = fsub(a.response, b.response);
    let den = fsub(a.challenge, b.challenge);
    finv(den).map(|inv| fmul(num, inv))
}

// -- the Existence Container --------------------------------------------------

pub const CONTAINER_LEN: usize = 1024;
const MAX_SHOWS: usize = 38;

/// A recorded show in the container's log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShowRecord {
    pub challenge: u64,
    pub response: u64,
    pub counterparty: u64,
}

/// One coin's Existence Container: exactly 1 KiB serialized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Container {
    pub coin: u64,
    pub nf: u64,
    pub asset: u64,
    pub value: u64,
    pub born: u64,
    pub owner: u64,
    pub line: LineKey,
    pub shows: Vec<ShowRecord>,
}

fn put_u64(buf: &mut [u8], at: usize, v: u64) {
    buf[at..at + 8].copy_from_slice(&v.to_be_bytes());
}
fn get_u64(buf: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(buf[at..at + 8].try_into().unwrap())
}

impl Container {
    pub fn to_bytes(&self) -> [u8; CONTAINER_LEN] {
        assert!(self.shows.len() <= MAX_SHOWS, "a container holds at most {MAX_SHOWS} shows");
        let mut b = [0u8; CONTAINER_LEN];
        b[0..4].copy_from_slice(b"POEC");
        b[4..6].copy_from_slice(&1u16.to_be_bytes());
        b[6..8].copy_from_slice(&(self.shows.len() as u16).to_be_bytes());
        put_u64(&mut b, 8, self.coin);
        put_u64(&mut b, 16, self.nf);
        put_u64(&mut b, 24, self.asset);
        put_u64(&mut b, 32, self.value);
        put_u64(&mut b, 40, self.born);
        put_u64(&mut b, 48, self.owner);
        put_u64(&mut b, 56, self.line.secret);
        put_u64(&mut b, 64, self.line.blind);
        for (i, s) in self.shows.iter().enumerate() {
            let at = 72 + i * 24;
            put_u64(&mut b, at, s.challenge);
            put_u64(&mut b, at + 8, s.response);
            put_u64(&mut b, at + 16, s.counterparty);
        }
        let sum = h("container", &[Part::Bytes(&b[0..992])]);
        b[992..1024].copy_from_slice(&sum[0..32]);
        b
    }

    pub fn from_bytes(b: &[u8]) -> Result<Container, String> {
        if b.len() != CONTAINER_LEN {
            return Err(format!("a container is exactly {CONTAINER_LEN} bytes"));
        }
        if &b[0..4] != b"POEC" {
            return Err("bad magic".into());
        }
        let sum = h("container", &[Part::Bytes(&b[0..992])]);
        if sum[0..32] != b[992..1024] {
            return Err("checksum mismatch — the container is damaged or forged".into());
        }
        let n = u16::from_be_bytes(b[6..8].try_into().unwrap()) as usize;
        if n > MAX_SHOWS {
            return Err("show log over capacity".into());
        }
        let mut shows = Vec::with_capacity(n);
        for i in 0..n {
            let at = 72 + i * 24;
            shows.push(ShowRecord {
                challenge: get_u64(b, at),
                response: get_u64(b, at + 8),
                counterparty: get_u64(b, at + 16),
            });
        }
        Ok(Container {
            coin: get_u64(b, 8),
            nf: get_u64(b, 16),
            asset: get_u64(b, 24),
            value: get_u64(b, 32),
            born: get_u64(b, 40),
            owner: get_u64(b, 48),
            line: LineKey { secret: get_u64(b, 56), blind: get_u64(b, 64) },
            shows,
        })
    }

    /// Record a show in the log (the wallet's own copy of where this coin
    /// has been shown — a second show at a new challenge is exactly what
    /// the log exists to prevent honestly, and to expose dishonestly).
    pub fn record_show(&mut self, s: &Show, counterparty: u64) -> Result<(), String> {
        if s.coin != self.coin {
            return Err("show of a different coin".into());
        }
        if self.shows.iter().any(|r| r.challenge == s.challenge) {
            return Err("this coin was already shown at that challenge".into());
        }
        if self.shows.len() >= MAX_SHOWS {
            return Err("show log full".into());
        }
        self.shows.push(ShowRecord { challenge: s.challenge, response: s.response, counterparty });
        Ok(())
    }
}

// -- merchant offline policy ----------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct MerchantPolicy {
    pub per_coin_limit: u64,
    pub per_customer_limit: u64,
    pub bond: Option<u128>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyError {
    CoinTooLarge,
    CustomerOverLimit,
    BondMissing,
}

impl MerchantPolicy {
    /// Accept an offline payment? Offline acceptance is bounded, never
    /// final: the coin's fate is decided when branches merge on-chain.
    pub fn accept(
        &self,
        coin_value: u64,
        customer_total_after: u64,
        bond_posted: u128,
    ) -> Result<(), PolicyError> {
        if coin_value > self.per_coin_limit {
            return Err(PolicyError::CoinTooLarge);
        }
        if customer_total_after > self.per_customer_limit {
            return Err(PolicyError::CustomerOverLimit);
        }
        if let Some(required) = self.bond {
            if bond_posted < required {
                return Err(PolicyError::BondMissing);
            }
        }
        Ok(())
    }
}

// -- slot vouchers --------------------------------------------------------------

/// A one-time claim on a service slot (a message slot, a relay hour).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Voucher {
    pub id: u64,
    pub issuer: u64,
    pub epoch: u64,
    pub slot: u64,
}

impl Voucher {
    pub fn issue(issuer: u64, epoch: u64, slot: u64, nonce: u64) -> Voucher {
        let id = h("voucher", &[Part::Nat(issuer), Part::Nat(epoch), Part::Nat(slot), Part::Nat(nonce)])[0..8]
            .try_into()
            .map(u64::from_be_bytes)
            .unwrap_or(0);
        Voucher { id, issuer, epoch, slot }
    }
}

/// Redeems each voucher exactly once.
#[derive(Default)]
pub struct VoucherBook {
    redeemed: std::collections::HashSet<u64>,
}

impl VoucherBook {
    pub fn redeem(&mut self, v: &Voucher) -> bool {
        self.redeemed.insert(v.id)
    }
}

// -- 1-2-5 splitting --------------------------------------------------------------

/// Split an amount into the 1-2-5 denominations (…, 1, 2, 5, 10, 20, 50,
/// …), digit by digit: at most 3 bills per decimal digit, so at most 18
/// bills under 10^6 and at most 27 for any grant-size amount (< 10^9).
pub fn split_125(amount: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let mut place: u64 = 1;
    let mut rest = amount;
    while rest > 0 {
        let digit = rest % 10;
        let mut d = digit;
        if d >= 5 {
            out.push(5 * place);
            d -= 5;
        }
        while d >= 2 {
            out.push(2 * place);
            d -= 2;
        }
        if d == 1 {
            out.push(place);
        }
        rest /= 10;
        place *= 10;
    }
    out.sort_unstable_by(|a, b| b.cmp(a));
    out
}
