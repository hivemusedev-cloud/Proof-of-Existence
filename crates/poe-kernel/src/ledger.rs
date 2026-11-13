//! The ledger and its five acts — a port of the Lean kernel's ledger layer
//! (`Note`, `AssetRec`, `Op`, `Ledger`, `act`, `runOps`, `genesis`).
//!
//! The ledger is "in the clear", exactly as in the Lean model: it holds every
//! note whole, as a transaction's proof would see it. Binding notes to proofs
//! belongs to the ZK layer, a later build step; the validity predicates here
//! mirror the Lean ones field for field.
//!
//! Note on names: the Lean epoch-closing act is `Op.tick` (the manual's
//! prose calls it the *close*).

use crate::{grant, emission, mem_b, nodup_b, COIN, ENVELOPE, HORIZON, RESERVE, WINDOW};

/// A note (Lean `Note`): birth mark `cm`, death mark (nullifier) `nf`,
/// asset, value, birth epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Note {
    pub cm: u64,
    pub nf: u64,
    pub asset: u64,
    pub value: u64,
    pub born: u64,
}

/// A registered asset (Lean `AssetRec`): identifier, issuer, cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssetRec {
    pub id: u64,
    pub issuer: u64,
    pub cap: u128,
}

/// The acts (Lean `Op`). An invalid act leaves the ledger unchanged.
#[derive(Clone, Debug, PartialEq)]
pub enum Op {
    /// Register a machine, naming the marks of its grant note (born at close).
    Join { machine: u64, operator: u64, note: Note },
    /// Renew a registered machine's claim after its term: names fresh grant
    /// marks like a join, and is paid alike at the close. One claim per
    /// machine per epoch, by join or renewal (the kernel's `claimants`).
    Renew { machine: u64, operator: u64, note: Note },
    /// Register a new asset with issuer and cap. Never the coin, never twice.
    Create { issuer: u64, asset: u64, cap: u128 },
    /// The issuer births notes of its asset, within the cap. Never the coin.
    Issue { issuer: u64, asset: u64, outs: Vec<Note> },
    /// Kill the inputs, birth the outputs; value conserved per asset; no fee.
    Transfer { ins: Vec<Note>, outs: Vec<Note> },
    /// Close the epoch: birth one equal grant per registration registered
    /// this epoch, under the module cap `cap`; burn is by the window rule.
    Tick { cap: u64 },
}

/// The ledger (Lean `Ledger`).
#[derive(Clone, Debug, PartialEq)]
pub struct Ledger {
    pub now: u64,
    pub machines: Vec<u64>,
    pub births: Vec<Note>,
    pub deaths: Vec<u64>,
    pub minted: u128,
    pub assets: Vec<AssetRec>,
    pub issues: Vec<Note>,
    /// The open epoch's registrations: the note each join names.
    pub regs: Vec<Note>,
    /// The machines that have claimed in the open epoch, by a join or by a
    /// renewal: one claim each, cleared at the close (Lean `claimants`).
    pub claimants: Vec<u64>,
}

fn cms(notes: &[Note]) -> Vec<u64> {
    notes.iter().map(|n| n.cm).collect()
}

fn dms(notes: &[Note]) -> Vec<u64> {
    notes.iter().map(|n| n.nf).collect()
}

/// Lean `sumV`: total value of a list of notes.
pub fn sum_v(notes: &[Note]) -> u128 {
    notes.iter().map(|n| n.value as u128).sum()
}

/// Lean `sumA`: total value of one asset in a list of notes.
pub fn sum_a(asset: u64, notes: &[Note]) -> u128 {
    notes
        .iter()
        .filter(|n| n.asset == asset)
        .map(|n| n.value as u128)
        .sum()
}

fn assets_of(notes: &[Note]) -> Vec<u64> {
    notes.iter().map(|n| n.asset).collect()
}

/// Lean `AliveAt`: inside its window at epoch `now`.
pub fn alive_at(now: u64, n: &Note) -> bool {
    now <= n.born.saturating_add(WINDOW)
}

fn mem_n(n: &Note, notes: &[Note]) -> bool {
    notes.iter().any(|m| m == n)
}

/// Lean `freshNote`: both marks new to births, deaths, and open registrations.
fn fresh_note(l: &Ledger, n: &Note) -> bool {
    !mem_b(n.cm, &cms(&l.births))
        && !mem_b(n.nf, &dms(&l.births))
        && !mem_b(n.nf, &l.deaths)
        && !mem_b(n.cm, &cms(&l.regs))
        && !mem_b(n.nf, &dms(&l.regs))
}

/// Lean `bornOk`: born no later than now, and alive now.
fn born_ok(l: &Ledger, n: &Note) -> bool {
    n.born <= l.now && alive_at(l.now, n)
}

/// Lean `freshOuts`.
fn fresh_outs(l: &Ledger, outs: &[Note]) -> bool {
    outs.iter().all(|n| born_ok(l, n))
        && outs.iter().all(|n| fresh_note(l, n))
        && nodup_b(&cms(outs))
        && nodup_b(&dms(outs))
}

/// Lean `validJoin`.
fn valid_join(l: &Ledger, machine: u64, n: &Note) -> bool {
    !mem_b(machine, &l.machines) && n.asset == COIN && fresh_note(l, n)
}

/// Lean `validRenew`: the mirror of `validJoin` with the machine condition
/// inverted — the machine must already be registered — plus the epoch guard:
/// it must not already have claimed in the open epoch. Whether its term has
/// closed and no evidence stands against it is a module fact, handed to the
/// kernel by the caller exactly as the close's cap is; the kernel carries no
/// proof fields, as with Join.
fn valid_renew(l: &Ledger, machine: u64, n: &Note) -> bool {
    mem_b(machine, &l.machines)
        && n.asset == COIN
        && fresh_note(l, n)
        && !mem_b(machine, &l.claimants)
}

/// Lean `validCreate`.
fn valid_create(l: &Ledger, asset: u64) -> bool {
    asset != COIN && !mem_b(asset, &l.assets.iter().map(|r| r.id).collect::<Vec<_>>())
}

fn find_asset<'a>(l: &'a Ledger, asset: u64) -> Option<&'a AssetRec> {
    l.assets.iter().find(|r| r.id == asset)
}

/// Lean `validIssue`.
fn valid_issue(l: &Ledger, who: u64, asset: u64, outs: &[Note]) -> bool {
    match find_asset(l, asset) {
        None => false,
        Some(r) => {
            r.issuer == who
                && asset != COIN
                && outs.iter().all(|n| n.asset == asset)
                && sum_a(asset, &l.issues) + sum_v(outs) <= r.cap
                && fresh_outs(l, outs)
        }
    }
}

/// Lean `inputOk`: a note exactly as born, not dead, inside its window.
fn input_ok(l: &Ledger, n: &Note) -> bool {
    mem_n(n, &l.births) && !mem_b(n.nf, &l.deaths) && alive_at(l.now, n)
}

/// Lean `shapeOk`.
fn shape_ok(ins: &[Note], outs: &[Note]) -> bool {
    !ins.is_empty()
        && ins.len() <= ENVELOPE
        && outs.len() <= ENVELOPE
        && outs
            .iter()
            .all(|n| mem_b(n.asset, &assets_of(ins)))
        && outs
            .iter()
            .all(|n| ins.iter().all(|i| i.born <= n.born))
        && !outs.is_empty()
        && outs.iter().all(|n| n.value > 0)
}

/// Lean `conserves`: per-asset value in equals value out.
fn conserves(ins: &[Note], outs: &[Note]) -> bool {
    let mut assets = assets_of(ins);
    assets.extend(assets_of(outs));
    assets.iter().all(|&a| sum_a(a, ins) == sum_a(a, outs))
}

/// Lean `validTransfer`.
fn valid_transfer(l: &Ledger, ins: &[Note], outs: &[Note]) -> bool {
    shape_ok(ins, outs)
        && ins.iter().all(|n| input_ok(l, n))
        && nodup_b(&dms(ins))
        && conserves(ins, outs)
        && fresh_outs(l, outs)
}

/// Lean `liveA`: live value of an asset — born, not dead, inside the window.
pub fn live_a(l: &Ledger, asset: u64) -> u128 {
    l.births
        .iter()
        .filter(|n| n.asset == asset && !mem_b(n.nf, &l.deaths) && alive_at(l.now, n))
        .map(|n| n.value as u128)
        .sum()
}

/// Lean `stamp`: a registration's marks rebirthed as the coin, value `g`,
/// born at epoch `e`.
fn stamp(e: u64, g: u64, regs: &[Note]) -> Vec<Note> {
    regs.iter()
        .map(|n| Note {
            cm: n.cm,
            nf: n.nf,
            asset: COIN,
            value: g,
            born: e,
        })
        .collect()
}

impl Ledger {
    /// Lean `genesis`: the reserve its one note and its coin minted, nothing
    /// dead, no machine, no asset, epoch zero.
    pub fn genesis() -> Ledger {
        Ledger {
            now: 0,
            machines: Vec::new(),
            births: vec![Note {
                cm: 0,
                nf: 0,
                asset: COIN,
                value: RESERVE as u64,
                born: 0,
            }],
            deaths: Vec::new(),
            minted: RESERVE,
            assets: Vec::new(),
            issues: Vec::new(),
            regs: Vec::new(),
            claimants: Vec::new(),
        }
    }

    /// Lean `act`: apply one act; an invalid act leaves the ledger as it was,
    /// and the clock stops below the horizon.
    pub fn act(&self, op: &Op) -> Ledger {
        let mut l = self.clone();
        match op {
            Op::Join { machine, note, .. } => {
                if valid_join(self, *machine, note) {
                    l.machines.insert(0, *machine);
                    l.regs.insert(0, *note);
                    l.claimants.insert(0, *machine);
                }
            }
            Op::Renew { machine, note, .. } => {
                if valid_renew(self, *machine, note) {
                    l.regs.insert(0, *note);
                    l.claimants.insert(0, *machine);
                }
            }
            Op::Create { issuer, asset, cap } => {
                if valid_create(self, *asset) {
                    l.assets.insert(
                        0,
                        AssetRec {
                            id: *asset,
                            issuer: *issuer,
                            cap: *cap,
                        },
                    );
                }
            }
            Op::Issue { issuer, asset, outs } => {
                if valid_issue(self, *issuer, *asset, outs) {
                    let mut births = outs.clone();
                    births.extend_from_slice(&self.births);
                    l.births = births;
                    let mut issues = outs.clone();
                    issues.extend_from_slice(&self.issues);
                    l.issues = issues;
                }
            }
            Op::Transfer { ins, outs } => {
                if valid_transfer(self, ins, outs) {
                    let mut births = outs.clone();
                    births.extend_from_slice(&self.births);
                    l.births = births;
                    let mut deaths = dms(ins);
                    deaths.extend_from_slice(&self.deaths);
                    l.deaths = deaths;
                }
            }
            Op::Tick { cap } => {
                if self.now + 1 < HORIZON {
                    let live = live_a(self, COIN);
                    let n = self.regs.len() as u64;
                    let g = grant(live, n, *cap);
                    let mut births = stamp(self.now, g, &self.regs);
                    births.extend_from_slice(&self.births);
                    l.births = births;
                    l.minted = self.minted + emission(live, n, *cap);
                    l.now = self.now + 1;
                    l.regs = Vec::new();
                    l.claimants = Vec::new();
                }
            }
        }
        l
    }

    /// Lean `runOps`: fold a list of acts over the ledger, in order.
    pub fn run_ops(&self, ops: &[Op]) -> Ledger {
        let mut l = self.clone();
        for op in ops {
            l = l.act(op);
        }
        l
    }

    /// Whether an act would be accepted (its validity predicate holds).
    /// An invalid act leaves the ledger unchanged, so this is exactly the
    /// verdict a node gives the act.
    pub fn accepts(&self, op: &Op) -> bool {
        match op {
            Op::Join { machine, note, .. } => valid_join(self, *machine, note),
            Op::Renew { machine, note, .. } => valid_renew(self, *machine, note),
            Op::Create { asset, .. } => valid_create(self, *asset),
            Op::Issue { issuer, asset, outs } => valid_issue(self, *issuer, *asset, outs),
            Op::Transfer { ins, outs } => valid_transfer(self, ins, outs),
            Op::Tick { .. } => self.now + 1 < HORIZON,
        }
    }

    /// Lean `inputOk`, exposed for the window theorem's Rust mirror: a note
    /// exactly as born, not dead, inside its window.
    pub fn is_input_ok(&self, n: &Note) -> bool {
        input_ok(self, n)
    }

    /// Lean `pruneL`: what a validator may keep. Births inside their window
    /// and the deaths among them; the machine and asset registries whole
    /// (a replayed join or creation must still be refused); each asset's
    /// remaining capacity in place of its issued notes; the open epoch's
    /// registrations and claims untouched. Everything else is forgotten.
    /// The Lean theorem `the_window_is_enough` proves input verdicts are
    /// unchanged; the store battery checks act verdicts on honest acts.
    pub fn pruned(&self) -> Ledger {
        let kept: Vec<Note> = self
            .births
            .iter()
            .copied()
            .filter(|n| alive_at(self.now, n))
            .collect();
        let kept_dms = dms(&kept);
        Ledger {
            now: self.now,
            machines: self.machines.clone(),
            births: kept,
            deaths: self
                .deaths
                .iter()
                .copied()
                .filter(|k| mem_b(*k, &kept_dms))
                .collect(),
            minted: self.minted,
            assets: self
                .assets
                .iter()
                .map(|r| AssetRec {
                    id: r.id,
                    issuer: r.issuer,
                    cap: r.cap.saturating_sub(sum_a(r.id, &self.issues)),
                })
                .collect(),
            issues: Vec::new(),
            regs: self.regs.clone(),
            claimants: self.claimants.clone(),
        }
    }
}
