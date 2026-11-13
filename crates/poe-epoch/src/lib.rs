//! poe-epoch — the money engine (BUILD_FLOW Step 6).
//!
//! The weekly close, computed exactly as the Tokenomics module defines
//! it (the definitions below are ports of `PoE.Tok` — ceiling, budget,
//! modCap, gate, potP, gatedPot, capP, pGrant — with the Lean file's own
//! constants):
//!
//! * **ceiling** — a claimant earns at most one ten-billionth of the coin
//!   not yet issued: `(SMAX − E) / 10^10`, `E` the economy's live coin.
//! * **budget** — an epoch's total grant budget read from `M`, the grants
//!   minted to date, as the least of three phase lines floored at the
//!   Genesis budget of 10^10: `M/50` (Growth), `2·10^12 + (M − 10^14)/250`
//!   (Expansion), `3.6·10^12 + (M − 5·10^14)/1000` (Maturity).
//! * **profile** — a launch's three genesis-fixed numbers: pot divisor
//!   (≥ 300), window (≥ 522), usage floor in thousandths. The module's
//!   cap is `min(modCap, gatedPotShare)`; handed to the kernel's close it
//!   can only lower the grant, never raise it — the kernel still applies
//!   its own pot/GMAX on top.
//!
//! Around the close the engine keeps what the kernel does not: **vesting**
//! (each grant unlocks 1/50 per heartbeat-credited epoch of its owner),
//! the **reserve's burn** (Version 1: the sealed reserve leaves the live
//! count at epoch 523, when its window closes), and **renewal evaluation**
//! (a term of 25 faithful epochs — heartbeat credited, storage challenge
//! answered from the last state root, no evidence — with at least half
//! the latest grant still bonded).

use poe_crypto::hash::H512;
use poe_kernel::ledger::{live_a, Ledger, Op};
use poe_kernel::{GMAX, RESERVE, SMAX, COIN};
use std::collections::HashMap;

// -- the tokenomics law, ported ----------------------------------------------

/// The ceiling's divisor (Lean `D`).
pub const D: u128 = 10_000_000_000;
/// The Genesis budget (Lean `EBOOT`).
pub const EBOOT: u128 = 10_000_000_000;
const TG: u128 = 50;
const TE: u128 = 250;
const TM: u128 = 1000;
const CGE: u128 = 100_000_000_000_000;
const CEM: u128 = 500_000_000_000_000;
const BGE: u128 = 2_000_000_000_000;
const BEM: u128 = 3_600_000_000_000;
/// Thousandths (Lean `MIL`): the usage gate's scale.
pub const MIL: u64 = 1000;

/// Lean `ceiling`: one part in D of the coin not yet issued.
pub fn ceiling(economy_live: u128) -> u128 {
    SMAX.saturating_sub(economy_live) / D
}

/// Lean `budget`: the epoch budget from grants minted to date.
pub fn budget(grants_to_date: u128) -> u128 {
    let growth = grants_to_date / TG;
    let expansion = BGE + grants_to_date.saturating_sub(CGE) / TE;
    let maturity = BEM + grants_to_date.saturating_sub(CEM) / TM;
    EBOOT.max(growth.min(expansion).min(maturity))
}

/// Lean `modCap`: the module's per-claimant cap before the profile's pot.
pub fn mod_cap(economy_live: u128, grants_to_date: u128, claimants: u64) -> u128 {
    if claimants == 0 {
        return 0;
    }
    ceiling(economy_live).min(budget(grants_to_date) / claimants as u128)
}

/// A launch profile (Lean `Profile`): genesis-fixed, admissible iff
/// `potdiv ≥ 300`, `window ≥ 522`, `1 ≤ floor ≤ 1000`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    pub potdiv: u64,
    pub window: u64,
    pub floor: u64,
}

impl Profile {
    pub fn ok(&self) -> bool {
        self.potdiv >= 300 && self.window >= 522 && (1..=MIL).contains(&self.floor)
    }
    /// The named profiles of the Tokenomics paper.
    pub const REFERENCE: Profile = Profile { potdiv: 300, window: 522, floor: 1000 };
    pub const SLOW_POT: Profile = Profile { potdiv: 1044, window: 522, floor: 1000 };
    pub const LONG_WINDOW: Profile = Profile { potdiv: 300, window: 1044, floor: 1000 };
    pub const SLOW_AND_LONG: Profile = Profile { potdiv: 1044, window: 1044, floor: 1000 };
    pub const USAGE_PACED: Profile = Profile { potdiv: 1044, window: 1044, floor: 100 };
}

/// Lean `gate`: the usage gate in thousandths (1000 = gate fully open).
pub fn gate(p: &Profile, usage_milli: u64) -> u128 {
    let u = usage_milli.min(MIL) as u128;
    p.floor as u128 + (MIL - p.floor) as u128 * u / MIL as u128
}

/// Lean `potP`: the profile's pot — one part in its divisor of headroom.
pub fn pot_p(p: &Profile, live: u128) -> u128 {
    SMAX.saturating_sub(live) / p.potdiv as u128
}

/// Lean `gatedPot`.
pub fn gated_pot(p: &Profile, live: u128, usage_milli: u64) -> u128 {
    pot_p(p, live) * gate(p, usage_milli) / MIL as u128
}

/// Lean `capP`: the cap handed to the kernel's close.
pub fn cap_p(
    p: &Profile,
    live: u128,
    economy_live: u128,
    grants_to_date: u128,
    claimants: u64,
    usage_milli: u64,
) -> u64 {
    if claimants == 0 {
        return 0;
    }
    let by_module = mod_cap(economy_live, grants_to_date, claimants);
    let by_pot = gated_pot(p, live, usage_milli) / claimants as u128;
    by_module.min(by_pot).min(u64::MAX as u128) as u64
}

/// Lean `pGrant`: one claimant's grant under a profile.
pub fn p_grant(
    p: &Profile,
    live: u128,
    economy_live: u128,
    grants_to_date: u128,
    claimants: u64,
    usage_milli: u64,
) -> u64 {
    poe_kernel::grant(live, claimants, cap_p(p, live, economy_live, grants_to_date, claimants, usage_milli))
}

// -- the engine ---------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Launch {
    /// Version 1, the fair launch: the reserve is sealed and burns at 523.
    FairV1,
    /// Version 2, the listed launch: the reserve is premine (Step 10 lanes).
    ListedV2,
}

/// One grant's vesting state: 1/50 unlocks per credited epoch.
#[derive(Clone, Debug)]
pub struct Vesting {
    pub machine: u64,
    pub grant_epoch: u64,
    pub total: u128,
    pub credited_epochs: u32,
}

impl Vesting {
    /// The amount unlocked so far: `total · credits / 50`, all of it at 50.
    pub fn vested(&self) -> u128 {
        if self.credited_epochs >= 50 {
            self.total
        } else {
            self.total * self.credited_epochs as u128 / 50
        }
    }
}

/// What one close did.
#[derive(Debug)]
pub struct CloseReport {
    pub epoch: u64,
    pub claimants: u64,
    pub cap_handed: u64,
    pub grant_each: u64,
    pub minted_this_close: u128,
    pub burned_this_close: u128,
}

pub struct EpochEngine {
    pub profile: Profile,
    pub launch: Launch,
    vesting: HashMap<(u64, u64), Vesting>,
    /// This epoch's accepted registrations, as (machine, note cm), in the
    /// order their acts landed. The kernel stamps grants over `regs`;
    /// the act stream is how the engine knows whose each grant is.
    pending: Vec<(u64, u64)>,
}

impl EpochEngine {
    pub fn new(profile: Profile, launch: Launch) -> EpochEngine {
        assert!(profile.ok(), "inadmissible profile");
        EpochEngine { profile, launch, vesting: HashMap::new(), pending: Vec::new() }
    }

    /// Apply one act to the ledger, remembering accepted joins and
    /// renewals as this epoch's registrations. (All other acts simply
    /// pass through to the kernel.)
    pub fn apply(&mut self, ledger: &Ledger, op: &Op) -> Ledger {
        let next = ledger.act(op);
        match op {
            Op::Join { machine, note, .. } | Op::Renew { machine, note, .. } => {
                if next.regs.len() > ledger.regs.len() {
                    self.pending.push((*machine, note.cm));
                }
            }
            _ => {}
        }
        next
    }

    /// The economy's live coin for the ceiling: all live coin except a
    /// still-sealed reserve (Version 1 before its burn).
    fn economy_live(&self, ledger: &Ledger) -> u128 {
        let live = live_a(ledger, COIN);
        if self.launch == Launch::FairV1 && ledger.now < 523 {
            live.saturating_sub(RESERVE)
        } else {
            live
        }
    }

    /// Run one weekly close on the ledger: compute the cap from the
    /// tokenomics law (claimants = this epoch's registrations, the
    /// kernel's `regs`), hand it to the kernel's Tick, credit this
    /// epoch's heartbeats against *existing* grants, then record the
    /// grants this close is born with (they start vesting next epoch).
    ///
    /// `credited` is the set of machines whose heartbeat this epoch is
    /// credited (poe-finality's rule: every owed vote cast, unrevoked).
    pub fn close(
        &mut self,
        ledger: &mut Ledger,
        usage_milli: u64,
        credited: &[u64],
    ) -> CloseReport {
        let epoch = ledger.now;
        let live = live_a(ledger, COIN);
        let economy = self.economy_live(ledger);
        let grants_to_date = ledger.minted.saturating_sub(RESERVE);
        let registrations = std::mem::take(&mut self.pending);
        let n = ledger.regs.len() as u64;
        debug_assert_eq!(n as usize, registrations.len(), "one reg per registration");
        let cap = cap_p(&self.profile, live, economy, grants_to_date, n, usage_milli);
        let grant_each = poe_kernel::grant(live, n, cap);

        // Burn accounting: value alive before that is not alive after.
        let before = ledger.clone();
        *ledger = ledger.act(&Op::Tick { cap });
        let mut burned = 0u128;
        for b in &before.births {
            if poe_kernel::ledger::alive_at(before.now, b)
                && !poe_kernel::ledger::alive_at(ledger.now, b)
            {
                burned += b.value as u128;
            }
        }

        // Credit this epoch's heartbeats against grants born earlier.
        for m in credited {
            for v in self.vesting.values_mut() {
                if v.machine == *m && v.credited_epochs < 50 {
                    v.credited_epochs += 1;
                }
            }
        }
        // Record this close's grants, one per registration.
        if grant_each > 0 {
            for (m, _cm) in &registrations {
                self.vesting.insert(
                    (*m, epoch),
                    Vesting { machine: *m, grant_epoch: epoch, total: grant_each as u128, credited_epochs: 0 },
                );
            }
        }

        CloseReport {
            epoch,
            claimants: n,
            cap_handed: cap,
            grant_each,
            minted_this_close: n as u128 * grant_each as u128,
            burned_this_close: burned,
        }
    }

    /// A machine's total vested (spendable) grant balance across grants.
    pub fn vested_balance(&self, machine: u64) -> u128 {
        self.vesting.values().filter(|v| v.machine == machine).map(|v| v.vested()).sum()
    }

    /// Version 1's reserve: sealed while its window is open, burned from
    /// epoch 523 — the epoch its 522-epoch window closes past it.
    pub fn reserve_burned(&self, epoch: u64) -> bool {
        self.launch == Launch::FairV1 && epoch >= 523
    }
}

// -- renewal ------------------------------------------------------------------

/// One epoch of a miner's term, as the renewal act reads it.
#[derive(Clone, Copy, Debug)]
pub struct FaithfulEpoch {
    pub heartbeat_credited: bool,
    pub storage_answered: bool,
    pub evidence_named: bool,
}

impl FaithfulEpoch {
    pub fn faithful(&self) -> bool {
        self.heartbeat_credited && self.storage_answered && !self.evidence_named
    }
}

/// The storage challenge of an epoch is its state root: a miner answers
/// by naming the root its own store holds (poe-store's chain). The answer
/// is right iff it equals the root on record for that epoch.
pub fn storage_answer_ok(roots: &[(u64, H512)], epoch: u64, claimed: &H512) -> bool {
    roots.iter().find(|(e, _)| *e == epoch).map(|(_, r)| r == claimed).unwrap_or(false)
}

/// Renewal eligibility under the act: a full term of 25 faithful epochs,
/// and at least half the latest grant still bonded.
pub fn renewal_eligible(term: &[FaithfulEpoch], bond_locked: u128, latest_grant: u128) -> bool {
    term.len() == 25
        && term.iter().all(|e| e.faithful())
        && bond_locked * 2 >= latest_grant
        && latest_grant > 0
}
