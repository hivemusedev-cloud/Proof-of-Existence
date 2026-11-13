//! poe-kernel — the Proof of Existence settlement kernel.
//!
//! A definition-for-definition Rust port of the verified Lean 4 kernel core
//! (`Proof_of_Existence_v1_1_1_CC.lean`, namespace `PoE`). Function names keep
//! the Lean names (snake_case) so every definition can be diffed against the
//! specification by eye. Where Lean uses unbounded `Nat`, this port uses
//! `u64` for heights/identifiers and `u128` for value sums; Lean's natural
//! division by zero is 0, and that semantics is preserved (see `pot_share`).
//!
//! Increment 1 scope: claims and settlement (`Spend`, `settle`, `register`,
//! `evidence`), multi-height settlement (`MultiSpend`, `settleM`), the money
//! constants and grant law (`pot`, `grant`, `emission`), a stateful
//! [`Registry`] over the kernel's ten registry kinds, and the ledger with its
//! five acts (see [`ledger`]).

pub mod ledger;

// ---------------------------------------------------------------------------
// Constants (Lean: WINDOW, HORIZON, SMAX, RESERVE, POTDIV, GMAX, COIN,
// ENVELOPE, VESTING, SLOTS)
// ---------------------------------------------------------------------------

/// Epochs a note lives unmoved before it burns (~10 years of weeks).
pub const WINDOW: u64 = 522;
/// The clock stops below 2^32 epochs.
pub const HORIZON: u64 = 1 << 32;
/// Hard cap of live coin: one quadrillion indivisible units.
pub const SMAX: u128 = 1_000_000_000_000_000;
/// Genesis reserve: 30% of the cap, a note no key opens.
pub const RESERVE: u128 = 300_000_000_000_000;
/// The pot is one three-hundredth of the headroom per close.
pub const POTDIV: u128 = 300;
/// Per-claimant grant ceiling inside the kernel grant law.
pub const GMAX: u64 = 400_000_000;
/// The coin is asset 0.
pub const COIN: u64 = 0;
/// A transfer carries at most 64 inputs and 64 outputs.
pub const ENVELOPE: usize = 64;
/// A grant vests over 50 credited heartbeats.
pub const VESTING: u64 = 50;
/// Spend/message slots per credited machine-epoch.
pub const SLOTS: u64 = 65_536;

// ---------------------------------------------------------------------------
// Boolean list helpers (Lean: memB, nodupB, allB over List Nat)
// ---------------------------------------------------------------------------

/// Lean `memB`: membership in a list of heights.
pub fn mem_b(n: u64, xs: &[u64]) -> bool {
    xs.iter().any(|&k| k == n)
}

/// Lean `nodupB`: no element occurs twice.
pub fn nodup_b(xs: &[u64]) -> bool {
    let mut seen: Vec<u64> = Vec::with_capacity(xs.len());
    for &x in xs {
        if seen.contains(&x) {
            return false;
        }
        seen.push(x);
    }
    true
}

// ---------------------------------------------------------------------------
// Claims and settlement (Lean: Spend, settle, register, firstTx, evidence)
// ---------------------------------------------------------------------------

/// A claim on a height (Lean `Spend`): `nf` is the height — the thing that
/// may happen at most once — and `tx` is the side, the act on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spend {
    pub tx: u64,
    pub nf: u64,
}

impl Spend {
    pub fn new(tx: u64, nf: u64) -> Self {
        Spend { tx, nf }
    }
}

/// The heights of a stream of spends (Lean `nfs`).
pub fn nfs(ss: &[Spend]) -> Vec<u64> {
    ss.iter().map(|s| s.nf).collect()
}

/// Lean `settle`: walk the stream in order against the registry; accept a
/// spend only while its height is unregistered; accepting registers the
/// height. Returns the accepted spends, in stream order. First side wins.
pub fn settle(registry: &[u64], stream: &[Spend]) -> Vec<Spend> {
    let mut r: Vec<u64> = registry.to_vec();
    let mut out: Vec<Spend> = Vec::new();
    for &s in stream {
        if !mem_b(s.nf, &r) {
            out.push(s);
            r.push(s.nf);
        }
    }
    out
}

/// Lean `register`: the registry after settling the stream — the starting
/// registry plus exactly the heights of the accepted spends, as a set.
pub fn register(registry: &[u64], stream: &[Spend]) -> Vec<u64> {
    let mut r: Vec<u64> = registry.to_vec();
    for &s in stream {
        if !mem_b(s.nf, &r) {
            r.push(s.nf);
        }
    }
    r
}

/// Lean `firstTx`: the side of the first spend on a height in a stream
/// (0 when the stream names the height nowhere — as in Lean).
pub fn first_tx(stream: &[Spend], nf: u64) -> u64 {
    for s in stream {
        if s.nf == nf {
            return s.tx;
        }
    }
    0
}

/// Lean `evidence`: given the full stream `ss` that fixes the canonical side
/// of every height, every spend in `list` whose side is not the canonical
/// one yields a pair `(canonical, offender)` on the same height. Canonical
/// spends yield nothing, so evidence never accuses the canonical claim.
pub fn evidence(ss: &[Spend], list: &[Spend]) -> Vec<(Spend, Spend)> {
    let mut out = Vec::new();
    for &s in list {
        let canon = first_tx(ss, s.nf);
        if s.tx != canon {
            out.push((Spend::new(canon, s.nf), s));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Multi-height claims (Lean: MultiSpend, freshAll, settleM, registerM)
// ---------------------------------------------------------------------------

/// A claim on several heights at once (Lean `MultiSpend`), settled
/// all-or-nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiSpend {
    pub tx: u64,
    pub hs: Vec<u64>,
}

/// Lean `freshAll`: every height is new to the registry, and no height is
/// named twice inside the claim itself.
pub fn fresh_all(registry: &[u64], hs: &[u64]) -> bool {
    hs.iter().all(|&n| !mem_b(n, registry)) && nodup_b(hs)
}

/// Lean `settleM`: accept a multi-spend only if all its heights are fresh;
/// accepting registers all of them.
pub fn settle_m(registry: &[u64], stream: &[MultiSpend]) -> Vec<MultiSpend> {
    let mut r: Vec<u64> = registry.to_vec();
    let mut out: Vec<MultiSpend> = Vec::new();
    for s in stream {
        if fresh_all(&r, &s.hs) {
            out.push(s.clone());
            r.extend_from_slice(&s.hs);
        }
    }
    out
}

/// Lean `registerM`: the registry after settling a multi-spend stream.
pub fn register_m(registry: &[u64], stream: &[MultiSpend]) -> Vec<u64> {
    let mut r: Vec<u64> = registry.to_vec();
    for s in stream {
        if fresh_all(&r, &s.hs) {
            r.extend_from_slice(&s.hs);
        }
    }
    r
}

// ---------------------------------------------------------------------------
// The money law inside the kernel (Lean: pot, potShare, grant, emission)
// ---------------------------------------------------------------------------

/// Lean `pot`: one three-hundredth of the headroom (cap minus live coin).
pub fn pot(live: u128) -> u128 {
    SMAX.saturating_sub(live) / POTDIV
}

/// Lean `potShare`: the pot divided among `n` claimants. Lean's `Nat`
/// division by zero is 0, so a close with no claimants emits nothing —
/// preserved here deliberately.
pub fn pot_share(live: u128, n: u64) -> u128 {
    if n == 0 {
        0
    } else {
        pot(live) / (n as u128)
    }
}

/// Lean `grant`: one claimant's grant — the pot share, capped by GMAX, and
/// capped again by `v`, the cap an attached module (e.g. tokenomics) hands
/// the close. A module can only lower the kernel grant, never raise it.
pub fn grant(live: u128, n: u64, v: u64) -> u64 {
    let by_pot = pot_share(live, n).min(GMAX as u128);
    by_pot.min(v as u128) as u64
}

/// Lean `emission`: what a close mints in total, `n * grant`.
pub fn emission(live: u128, n: u64, v: u64) -> u128 {
    (n as u128) * (grant(live, n, v) as u128)
}

// ---------------------------------------------------------------------------
// The ten registries (Lean abbrevs: CoinDeath, MachineBirth, Vote, KeyUse,
// Slot, Proposal, Admission, ContractVersion, OracleTick, MessageTag)
// ---------------------------------------------------------------------------

/// The kernel's ten registries. All of them run the same settlement law;
/// only the meaning of the height differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RegistryKind {
    CoinDeath,
    MachineBirth,
    Vote,
    KeyUse,
    Slot,
    Proposal,
    Admission,
    ContractVersion,
    OracleTick,
    MessageTag,
}

/// What a [`Registry::claim`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// The height was fresh; the claim is canonical for its height.
    Accepted,
    /// The same side claimed the same height again; nothing changes and
    /// there is no evidence (evidence never accuses the canonical claim).
    Duplicate,
    /// A different side claimed a taken height; the pair
    /// `(canonical, offender)` has been recorded as evidence.
    Evidence,
}

/// A stateful registry: one instance of the settlement law over one kind of
/// height, keeping its accepted claims and its evidence.
#[derive(Clone, Debug)]
pub struct Registry {
    pub kind: RegistryKind,
    heights: Vec<u64>,
    accepted: Vec<Spend>,
    evidence: Vec<(Spend, Spend)>,
}

impl Registry {
    pub fn new(kind: RegistryKind) -> Self {
        Registry {
            kind,
            heights: Vec::new(),
            accepted: Vec::new(),
            evidence: Vec::new(),
        }
    }

    /// Settle one claim. First side wins; a second, different side is
    /// refused and kept as evidence.
    pub fn claim(&mut self, s: Spend) -> ClaimOutcome {
        if !mem_b(s.nf, &self.heights) {
            self.heights.push(s.nf);
            self.accepted.push(s);
            ClaimOutcome::Accepted
        } else if first_tx(&self.accepted, s.nf) == s.tx {
            ClaimOutcome::Duplicate
        } else {
            let canon = Spend::new(first_tx(&self.accepted, s.nf), s.nf);
            self.evidence.push((canon, s));
            ClaimOutcome::Evidence
        }
    }

    /// Settle a whole stream, in order.
    pub fn claim_all(&mut self, stream: &[Spend]) -> Vec<ClaimOutcome> {
        stream.iter().map(|&s| self.claim(s)).collect()
    }

    /// Rebuild a registry from persisted parts (storage reload). The parts
    /// are trusted to have come from a `Registry` — heights are the
    /// accepted spends' heights, in acceptance order.
    pub fn restore(
        kind: RegistryKind,
        heights: Vec<u64>,
        accepted: Vec<Spend>,
        evidence: Vec<(Spend, Spend)>,
    ) -> Registry {
        Registry {
            kind,
            heights,
            accepted,
            evidence,
        }
    }

    pub fn is_registered(&self, nf: u64) -> bool {
        mem_b(nf, &self.heights)
    }

    pub fn accepted(&self) -> &[Spend] {
        &self.accepted
    }

    pub fn evidence(&self) -> &[(Spend, Spend)] {
        &self.evidence
    }

    pub fn heights(&self) -> &[u64] {
        &self.heights
    }
}
