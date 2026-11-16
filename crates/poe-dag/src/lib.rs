//! poe-dag — BlockDAG assembly and GHOSTDAG linearization.
//!
//! Implemented from the PHANTOM/GHOSTDAG spec (Sompolinsky–Zohar), as
//! BUILD_FLOW Step 4 requires: this replaces the manual's *imported*
//! ordering assumption with code whose agreement property is then tested
//! directly (see the insertion-order battery below).
//!
//! A block is a claim on `(machine, round)` carrying opaque payload bytes
//! (in the node, the round's acts). Its id is `H("block", …)` over the
//! machine, round, parents and payload, so the DAG is content-addressed:
//! the same block has the same id on every node, and the linearization
//! below is a pure function of the block set — never of arrival order.
//!
//! GHOSTDAG, per block: the *selected parent* is the parent of greatest
//! blue score (ties by smallest id). The block inherits the selected
//! parent's blues plus the parent itself; the remaining *mergeset* (the
//! other parents' pasts) is then considered in decreasing blue-score
//! order, and a candidate joins the blues iff at most `k` of the current
//! blues lie in its anticone — otherwise it is red. The linearization is
//! the recursive order: selected parent's order, then each mergeset
//! block's order in consideration order, then the block itself.
//!
//! **Bounded memory (2026-11-15 redesign, DAG_MEMORY_DESIGN.md).** The
//! original implementation stored, per block, its full ancestor set and
//! its full blue/red lists — Θ(N²) memory (≈4.94 GB RSS at the 33k-block
//! epoch-209 testnet state; one node per 8 GB host). This implementation
//! stores per block only:
//!   * a *window* of ancestors within `WINDOW_ROUNDS` rounds, plus a
//!     *frontier* cut set (the deep ancestors that are parents of window
//!     blocks) — together an EXACT ancestor oracle: `is_ancestor`
//!     answers by window lookup or by descending frontier cuts, and is
//!     provably identical to the full-set answer for any window size
//!     (the window is a speed/memory constant, never an approximation);
//!   * the GHOSTDAG *rope*: the candidates this block itself accepted
//!     (blues) or rejected (reds). A block's full blues are
//!     `blues(chosen) ++ [chosen] ++ accepted`, materialized on demand
//!     by walking selected-parent links — O(1) retained per block.
//! The Manual's own law licenses the shape: "the window is enough, a
//! validator that forgets every closed window giving every input the
//! verdict of one that forgot nothing." Equivalence with the original
//! implementation is pinned by the differential battery in
//! `tests/differential.rs` against a verbatim copy of it.

use poe_crypto::hash::{h, Part, H512};
use std::collections::{HashMap, HashSet};

pub type BlockId = H512;

/// Ancestor-window depth in rounds. Purely a speed/memory constant:
/// ancestor queries deeper than the window are answered exactly by
/// frontier descent (see `Anc`). Larger = faster deep queries, more
/// retained ids per block.
pub const WINDOW_ROUNDS: u64 = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub machine: u64,
    pub round: u64,
    pub parents: Vec<BlockId>,
    pub payload: Vec<u8>,
    pub id: BlockId,
}

impl Block {
    pub fn new(machine: u64, round: u64, parents: Vec<BlockId>, payload: Vec<u8>) -> Block {
        let mut parent_bytes = Vec::with_capacity(parents.len() * 64);
        for p in &parents {
            parent_bytes.extend_from_slice(p);
        }
        let id = h(
            "block",
            &[
                Part::Nat(machine),
                Part::Nat(round),
                Part::Bytes(&parent_bytes),
                Part::Bytes(&payload),
            ],
        );
        Block { machine, round, parents, payload, id }
    }
}

/// GHOSTDAG data for one block, materialized on demand from the stored
/// rope (see `GhostCore`). Same shape the original implementation
/// stored directly.
#[derive(Clone, Debug)]
pub struct GhostData {
    pub chosen: Option<BlockId>,
    /// Blue blocks in this block's past, in the order they were accepted.
    pub blues: Vec<BlockId>,
    pub reds: Vec<BlockId>,
    /// The mergeset in the order it was considered (blues and reds alike).
    pub mergeset_order: Vec<BlockId>,
    pub blue_score: u64,
}

/// One block's full retained state, as carried by `DagState`:
/// the block itself, its GHOSTDAG core (with compaction base lists),
/// and its ancestor-oracle window/frontier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockState {
    pub block: Block,
    pub chosen: Option<BlockId>,
    pub mergeset_order: Vec<BlockId>,
    pub accepted: Vec<BlockId>,
    pub rejected: Vec<BlockId>,
    pub blue_score: u64,
    pub base_blues: Vec<BlockId>,
    pub base_reds: Vec<BlockId>,
    pub window: Vec<BlockId>,
    pub frontier: Vec<BlockId>,
}

/// A whole DAG's retained state (see `Dag::export_state`): the
/// blocks' states plus the compaction seeds — pruned blocks' rounds,
/// and the parents/oracle of the bounded seed band around the
/// pruning point — and the tip-guard set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DagState {
    pub genesis: Option<BlockId>,
    pub blocks: Vec<BlockState>,
    pub seed_rounds: Vec<(BlockId, u64)>,
    pub seed_parents: Vec<(BlockId, Vec<BlockId>)>,
    pub seed_anc: Vec<(BlockId, Vec<BlockId>, Vec<BlockId>)>,
    pub pruned_children: Vec<BlockId>,
}

/// What is actually retained per block: the selected parent, the blue
/// score, the mergeset in consideration order, and the two rope links —
/// the candidates this block accepted into / rejected from the blues
/// inherited from its selected parent. Full blues of a block are
/// `blues(chosen) ++ [chosen] ++ accepted`; full reds are
/// `reds(chosen) ++ rejected`.
#[derive(Clone, Debug)]
struct GhostCore {
    chosen: Option<BlockId>,
    mergeset_order: Vec<BlockId>,
    accepted: Vec<BlockId>,
    rejected: Vec<BlockId>,
    blue_score: u64,
    /// Compaction cut data (2026-11-16): when pruning drops this
    /// block's chosen parent, the chain is cut here — `chosen`
    /// becomes None and the dropped parent's contribution is
    /// materialized into these base lists, so `blues_of`/`reds_of`
    /// return exactly the pre-prune lists. Empty for every block
    /// that was never cut (including genesis).
    base_blues: Vec<BlockId>,
    base_reds: Vec<BlockId>,
}

/// Exact ancestor oracle data for one block.
/// `window`: the block itself plus every ancestor with
/// `round >= round(block) - WINDOW_ROUNDS`, sorted.
/// `frontier`: every ancestor with `round < round(block) - WINDOW_ROUNDS`
/// that is a parent of a window block (or of the block itself), sorted —
/// the cut through which all deeper ancestors are reached.
/// Invariant (proved in DAG_MEMORY_DESIGN.md §4): every ancestor `a` of
/// the block is either in `window` (when `round(a)` is at/above the
/// cutoff), or in `frontier`, or an ancestor of a `frontier` member.
#[derive(Clone, Debug)]
struct Anc {
    window: Vec<BlockId>,
    frontier: Vec<BlockId>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DagError {
    UnknownParent,
    SecondGenesis,
    Duplicate,
}

pub struct Dag {
    blocks: HashMap<BlockId, Block>,
    ghost: HashMap<BlockId, GhostCore>,
    anc: HashMap<BlockId, Anc>,
    children: HashMap<BlockId, Vec<BlockId>>,
    genesis: Option<BlockId>,
    /// Compaction seed data (2026-11-16): what survives of a pruned
    /// block. `seed_rounds` holds the round of EVERY pruned block
    /// (8 bytes each — the round check in `is_ancestor` must keep
    /// working for pruned ids, because retained blocks' blue lists
    /// and windows still name them). `seed_parents` / `seed_anc`
    /// hold the parents / ancestor-oracle of only the pruned blocks
    /// that retained data can still reach: blocks named in a
    /// retained block's window (their parents feed the frontier
    /// computation of future inserts) and blocks on a retained
    /// block's frontier-descent closure (their oracle answers deep
    /// ancestry queries). Both sets are bounded bands around the
    /// pruning point, independent of total history length.
    seed_rounds: HashMap<BlockId, u64>,
    seed_parents: HashMap<BlockId, Vec<BlockId>>,
    seed_anc: HashMap<BlockId, Anc>,
    /// Blocks that have at least one pruned child. Such a block must
    /// never surface as a tip: in the unpruned DAG it is not one,
    /// and a future proposal taking it as a parent would diverge.
    pruned_children: HashSet<BlockId>,
    /// The GHOSTDAG cluster parameter: how many blue blocks may sit in a
    /// candidate's anticone before the candidate turns red.
    pub k: u64,
}

impl Dag {
    pub fn new(k: u64) -> Dag {
        Dag {
            blocks: HashMap::new(),
            ghost: HashMap::new(),
            anc: HashMap::new(),
            children: HashMap::new(),
            genesis: None,
            seed_rounds: HashMap::new(),
            seed_parents: HashMap::new(),
            seed_anc: HashMap::new(),
            pruned_children: HashSet::new(),
            k,
        }
    }

    pub fn get(&self, id: &BlockId) -> Option<&Block> {
        self.blocks.get(id)
    }

    fn cutoff(round: u64) -> u64 {
        round.saturating_sub(WINDOW_ROUNDS)
    }

    fn round_of(&self, id: &BlockId) -> Option<u64> {
        self.blocks
            .get(id)
            .map(|b| b.round)
            .or_else(|| self.seed_rounds.get(id).copied())
    }

    /// A block's parents: from the block itself when retained, else
    /// from the compaction seeds (a retained block's mergeset walk
    /// and frontier computation can step onto a pruned parent).
    fn parents_of(&self, id: &BlockId) -> Vec<BlockId> {
        if let Some(b) = self.blocks.get(id) {
            return b.parents.clone();
        }
        self.seed_parents.get(id).cloned().unwrap_or_default()
    }

    /// Materialize a block's full blue list by walking selected-parent
    /// links: `blues(b) = blues(chosen) ++ [chosen] ++ accepted(b)`.
    fn blues_of(&self, id: &BlockId) -> Vec<BlockId> {
        // Collect the selected-parent chain down to genesis, then unwind.
        let mut chain: Vec<&GhostCore> = Vec::new();
        let mut cur = *id;
        loop {
            let g = &self.ghost[&cur];
            chain.push(g);
            match g.chosen {
                Some(c) => cur = c,
                None => break,
            }
        }
        // Seed with the deepest core's compaction base (empty unless
        // the chain was cut there by pruning — then it is exactly the
        // blues the dropped chosen parent contributed).
        let mut out: Vec<BlockId> = chain.last().expect("nonempty chain").base_blues.clone();
        // Unwind from genesis upward: each level contributes its chosen
        // (which is the next level down's block) then its accepted.
        for (i, g) in chain.iter().enumerate().rev() {
            if i + 1 < chain.len() {
                // The block whose core sits one level deeper is this
                // level's chosen.
                let chosen_id = g.chosen.expect("non-genesis level has a chosen");
                out.push(chosen_id);
            }
            out.extend(g.accepted.iter().copied());
        }
        out
    }

    /// Materialize a block's full red list, the mirror of `blues_of`.
    fn reds_of(&self, id: &BlockId) -> Vec<BlockId> {
        let mut chain: Vec<&GhostCore> = Vec::new();
        let mut cur = *id;
        loop {
            let g = &self.ghost[&cur];
            chain.push(g);
            match g.chosen {
                Some(c) => cur = c,
                None => break,
            }
        }
        let mut out: Vec<BlockId> = chain.last().expect("nonempty chain").base_reds.clone();
        for g in chain.iter().rev() {
            out.extend(g.rejected.iter().copied());
        }
        out
    }

    pub fn ghost(&self, id: &BlockId) -> Option<GhostData> {
        let g = self.ghost.get(id)?;
        Some(GhostData {
            chosen: g.chosen,
            blues: self.blues_of(id),
            reds: self.reds_of(id),
            mergeset_order: g.mergeset_order.clone(),
            blue_score: g.blue_score,
        })
    }

    pub fn blue_score(&self, id: &BlockId) -> u64 {
        self.ghost.get(id).map(|g| g.blue_score).unwrap_or(0)
    }

    /// Exact ancestor test — identical answers to the original full-set
    /// implementation (pinned by the differential battery).
    pub fn is_ancestor(&self, anc: &BlockId, of: &BlockId) -> bool {
        let (Some(ra), Some(ro)) = (self.round_of(anc), self.round_of(of)) else {
            return false;
        };
        if ra > ro {
            return false;
        }
        // The oracle data lives with the block when retained, and in
        // the compaction seeds when `of` itself was pruned (frontier
        // descent steps onto pruned blocks by design).
        let Some(a) = self.anc.get(of).or_else(|| self.seed_anc.get(of)) else {
            return false;
        };
        if ra >= Self::cutoff(ro) {
            return a.window.binary_search(anc).is_ok();
        }
        if a.frontier.binary_search(anc).is_ok() {
            return true;
        }
        a.frontier.iter().any(|f| self.is_ancestor(anc, f))
    }

    /// Current tips (blocks with no children), in deterministic order.
    pub fn tips(&self) -> Vec<BlockId> {
        let mut t: Vec<BlockId> = self
            .blocks
            .keys()
            .filter(|&id| {
                self.children.get(id).map(|c| c.is_empty()).unwrap_or(true)
                    && !self.pruned_children.contains(id)
            })
            .copied()
            .collect();
        t.sort();
        t
    }

    /// The selected tip: greatest blue score, ties by smallest id — the
    /// block whose past the network currently treats as the main story.
    pub fn selected_tip(&self) -> Option<BlockId> {
        self.tips()
            .into_iter()
            .max_by(|a, b| {
                self.blue_score(a)
                    .cmp(&self.blue_score(b))
                    .then(b.cmp(a)) // smallest id wins the tie
            })
    }

    /// The mergeset of a new block: every block in a non-chosen parent's
    /// past that is not in the chosen parent's past (pasts include the
    /// parents themselves). Computed by DFS from the non-chosen parents,
    /// pruned wherever a block is in the chosen past (its ancestors are
    /// too, by transitivity) — visits each mergeset block once.
    fn mergeset_of(&self, chosen: &BlockId, others: &[BlockId]) -> HashSet<BlockId> {
        let mut out: HashSet<BlockId> = HashSet::new();
        let mut seen: HashSet<BlockId> = HashSet::new();
        let mut stack: Vec<BlockId> = others.to_vec();
        while let Some(x) = stack.pop() {
            if !seen.insert(x) {
                continue;
            }
            if self.is_ancestor(&x, chosen) {
                continue; // in the chosen past: prune the whole subtree
            }
            out.insert(x);
            stack.extend(self.parents_of(&x));
        }
        out
    }

    pub fn insert(&mut self, block: Block) -> Result<(), DagError> {
        if self.blocks.contains_key(&block.id) {
            return Err(DagError::Duplicate);
        }
        if block.parents.is_empty() {
            if self.genesis.is_some() {
                return Err(DagError::SecondGenesis);
            }
            self.genesis = Some(block.id);
        }
        for p in &block.parents {
            if !self.blocks.contains_key(p) {
                return Err(DagError::UnknownParent);
            }
        }

        // Ancestor oracle data: retained = {block} ∪ ⋃ parents'
        // (window ∪ frontier); window keeps the part at/above this
        // block's cutoff, and the frontier is the deep part's boundary —
        // deep retained blocks that are parents of window blocks.
        let anc = {
            let mut retained: HashSet<BlockId> = HashSet::new();
            retained.insert(block.id);
            for p in &block.parents {
                let pa = &self.anc[p];
                retained.extend(pa.window.iter().copied());
                retained.extend(pa.frontier.iter().copied());
            }
            let cut = Self::cutoff(block.round);
            // Rounds come from `round_of`, not `blocks`: after a
            // prune, a retained id may name a pruned block, whose
            // round lives in the seed map. Defaulting those to the
            // new block's own round (the pre-compaction behavior,
            // correct only for the new block itself) would promote
            // deep pruned ancestors into the window, where the
            // round-gated window branch of `is_ancestor` never looks
            // for them — the replay gate caught exactly that.
            let mut window: Vec<BlockId> = retained
                .iter()
                .copied()
                .filter(|x| self.round_of(x).unwrap_or(block.round) >= cut)
                .collect();
            window.sort();
            window.dedup();
            let winset: HashSet<BlockId> = window.iter().copied().collect();
            let mut frontier: Vec<BlockId> = Vec::new();
            for y in &window {
                // Parents of every window block; the new block itself is
                // not in `blocks` yet, so its parents come from `block`.
                // A window block may have been pruned (its id persists
                // in windows by design) — `parents_of` falls back to
                // the compaction seeds for those.
                let parents: Vec<BlockId> = if *y == block.id {
                    block.parents.clone()
                } else {
                    self.parents_of(y)
                };
                for par in &parents {
                    if !winset.contains(par) {
                        frontier.push(*par);
                    }
                }
            }
            frontier.sort();
            frontier.dedup();
            Anc { window, frontier }
        };

        let ghost = if block.parents.is_empty() {
            GhostCore {
                chosen: None,
                mergeset_order: vec![],
                accepted: vec![],
                rejected: vec![],
                blue_score: 0,
                base_blues: vec![],
                base_reds: vec![],
            }
        } else {
            // Selected parent: greatest blue score, tie -> smallest id.
            let chosen = *block
                .parents
                .iter()
                .max_by(|a, b| {
                    self.blue_score(a)
                        .cmp(&self.blue_score(b))
                        .then(b.cmp(a))
                })
                .expect("non-empty parents");
            // Mergeset: every other parent's past, minus the chosen past.
            let others: Vec<BlockId> =
                block.parents.iter().copied().filter(|p| *p != chosen).collect();
            let mergeset = self.mergeset_of(&chosen, &others);
            // Consider in decreasing blue-score order, ties by id.
            let mut order: Vec<BlockId> = mergeset.into_iter().collect();
            order.sort_by(|a, b| {
                self.blue_score(b)
                    .cmp(&self.blue_score(a))
                    .then(a.cmp(b))
            });
            // The growing blues list: chosen's blues, then chosen, then
            // each accepted candidate in consideration order.
            let mut blues: Vec<BlockId> = self.blues_of(&chosen);
            blues.push(chosen);
            let mut accepted: Vec<BlockId> = Vec::new();
            let mut rejected: Vec<BlockId> = Vec::new();
            for cand in &order {
                let in_anticone = blues
                    .iter()
                    .filter(|&y| !self.is_ancestor(y, cand) && !self.is_ancestor(cand, y))
                    .count() as u64;
                if in_anticone <= self.k {
                    blues.push(*cand);
                    accepted.push(*cand);
                } else {
                    rejected.push(*cand);
                }
            }
            let blue_score = blues.len() as u64;
            GhostCore {
                chosen: Some(chosen),
                mergeset_order: order,
                accepted,
                rejected,
                blue_score,
                base_blues: vec![],
                base_reds: vec![],
            }
        };

        for p in &block.parents {
            self.children.entry(*p).or_default().push(block.id);
        }
        self.children.entry(block.id).or_default();
        self.anc.insert(block.id, anc);
        self.ghost.insert(block.id, ghost);
        self.blocks.insert(block.id, block);
        Ok(())
    }

    /// Epoch compaction (2026-11-16): drop the history below a
    /// pruning point, exactly — every future insert, blue score,
    /// ancestry answer (over retained blocks, and over pruned ids
    /// where retained data still names them), tip selection, and
    /// vote target is identical to the unpruned DAG. The design is
    /// the one specified in PROPOSAL_LIVENESS_AND_DAG_STORAGE.md §2,
    /// with all three of its conditions:
    ///
    /// 1. **Pruning point, not an epoch line.** `anchor` must be an
    ///    ancestor of every current tip; otherwise nothing is
    ///    dropped (returns 0). Every dropped block is then in the
    ///    past of every future insert's selected parent, so a
    ///    dropped block can never sit in a future candidate's
    ///    anticone — the divergence the naive form suffered.
    /// 2. **Reference closure.** A candidate (strict ancestor of the
    ///    anchor) survives if any surviving block reaches it through
    ///    `mergeset_order` / `accepted` / `rejected` — the lists the
    ///    linearization walk and the rope materialization traverse.
    ///    Two reference kinds are discharged instead of protected:
    ///    *chosen* links are cut, with the dropped parent's blues
    ///    and reds materialized into the survivor's base lists (so
    ///    `ghost()` of every survivor is byte-identical), and
    ///    *parent* links are discharged into the seed maps below.
    /// 3. **Seed-aware state.** A pruned block leaves behind exactly
    ///    what retained data can still reach: its round (always —
    ///    retained blue lists and windows name pruned ids, and the
    ///    round check must keep answering), and — for the bounded
    ///    band of pruned blocks named in survivors' windows or on
    ///    their frontier-descent closure — its parents and its
    ///    ancestor oracle. `export_state`/`from_state` carry the
    ///    seeds, so a snapshot of a pruned DAG restores exactly,
    ///    including blocks whose parents were pruned (they restore
    ///    from their carried cores, never by re-insertion).
    ///
    /// What pruning gives up, by design: `linearize()` ranges over
    /// the retained DAG only (the dropped prefix is gone from the
    /// order; the relative order of retained blocks at and above
    /// the anchor region is unchanged, and the node's
    /// consensus-critical uses — the vote target among recent
    /// rounds, application via the finalized map — never read the
    /// dropped prefix), and `get()` no longer returns pruned
    /// blocks. Returns the number of blocks dropped.
    pub fn prune(&mut self, anchor: &BlockId) -> usize {
        if !self.blocks.contains_key(anchor) {
            return 0;
        }
        // (1) The pruning-point check.
        for t in self.tips() {
            if !self.is_ancestor(anchor, &t) {
                return 0;
            }
        }
        // Candidates: strict ancestors of the anchor.
        let candidates: HashSet<BlockId> = self
            .blocks
            .keys()
            .copied()
            .filter(|x| *x != *anchor && self.is_ancestor(x, anchor))
            .collect();
        if candidates.is_empty() {
            return 0;
        }
        // (2) Protection: worklist over the protecting references
        // (mergeset_order / accepted / rejected), seeded with every
        // non-candidate. A candidate referenced by a retained block
        // is retained, and its own references then protect too.
        let mut retained: HashSet<BlockId> =
            self.blocks.keys().copied().filter(|x| !candidates.contains(x)).collect();
        let mut queue: Vec<BlockId> = retained.iter().copied().collect();
        while let Some(r) = queue.pop() {
            let g = &self.ghost[&r];
            for x in g.mergeset_order.iter().chain(&g.accepted).chain(&g.rejected) {
                if candidates.contains(x) && retained.insert(*x) {
                    queue.push(*x);
                }
            }
        }
        let drop_set: HashSet<BlockId> = candidates.difference(&retained).copied().collect();
        if drop_set.is_empty() {
            return 0;
        }
        // Cut every survivor's chosen link into the drop set,
        // materializing the dropped parent's blues/reds into the
        // survivor's base lists — computed now, while the chains
        // are still intact.
        let cuts: Vec<(BlockId, Vec<BlockId>, Vec<BlockId>)> = self
            .ghost
            .iter()
            .filter(|(id, _)| !drop_set.contains(*id))
            .filter_map(|(id, g)| g.chosen.filter(|c| drop_set.contains(c)).map(|c| (*id, c)))
            .map(|(id, c)| {
                let mut base_blues = self.blues_of(&c);
                base_blues.push(c);
                (id, base_blues, self.reds_of(&c))
            })
            .collect();
        for (id, base_blues, base_reds) in cuts {
            let g = self.ghost.get_mut(&id).expect("survivor core");
            g.base_blues = base_blues;
            g.base_reds = base_reds;
            g.chosen = None;
        }
        // (3) Seed sets: pruned blocks named in a survivor's window
        // or frontier, closed under frontier (and window) descent —
        // a bounded band around the pruning point. The sources are
        // every oracle that survives this prune: retained blocks'
        // own, AND the seeds carried from earlier prunes — a descent
        // that passes through an old seed continues into that seed's
        // frontier, whose members are being dropped only now. (The
        // first version of this scan skipped the old seeds, and the
        // replay gate caught a lost ancestry answer exactly there.)
        let mut seed_set: HashSet<BlockId> = HashSet::new();
        let mut sq: Vec<BlockId> = Vec::new();
        for (id, a) in &self.anc {
            if drop_set.contains(id) {
                continue;
            }
            for x in a.window.iter().chain(&a.frontier) {
                if drop_set.contains(x) && seed_set.insert(*x) {
                    sq.push(*x);
                }
            }
        }
        for a in self.seed_anc.values() {
            for x in a.window.iter().chain(&a.frontier) {
                if drop_set.contains(x) && seed_set.insert(*x) {
                    sq.push(*x);
                }
            }
        }
        while let Some(f) = sq.pop() {
            for x in self.anc[&f].window.iter().chain(&self.anc[&f].frontier) {
                if drop_set.contains(x) && seed_set.insert(*x) {
                    sq.push(*x);
                }
            }
        }
        // Move the seeds out, mark tip guards, then remove the blocks.
        let dropped = drop_set.len();
        for x in &drop_set {
            self.seed_rounds.insert(*x, self.blocks[x].round);
            if seed_set.contains(x) {
                self.seed_parents.insert(*x, self.blocks[x].parents.clone());
                self.seed_anc.insert(*x, self.anc[x].clone());
            }
            for p in &self.blocks[x].parents {
                if !drop_set.contains(p) {
                    self.pruned_children.insert(*p);
                }
            }
        }
        for x in &drop_set {
            self.blocks.remove(x);
            self.ghost.remove(x);
            self.anc.remove(x);
            self.children.remove(x);
        }
        for c in self.children.values_mut() {
            c.retain(|id| !drop_set.contains(id));
        }
        dropped
    }

    /// The full retained state of the DAG, in a form a snapshot can
    /// carry and `from_state` can restore exactly — including the
    /// compaction seeds, so a pruned DAG survives a snapshot/restore
    /// round trip with every answer intact. (The blocks-only path —
    /// `blocks()` + re-insertion — cannot do this: a block whose
    /// parents were pruned has nothing to re-insert against, and
    /// its precomputed core is the only exact record.)
    pub fn export_state(&self) -> DagState {
        let mut blocks: Vec<BlockState> = self
            .blocks
            .values()
            .map(|b| {
                let g = &self.ghost[&b.id];
                let a = &self.anc[&b.id];
                BlockState {
                    block: b.clone(),
                    chosen: g.chosen,
                    mergeset_order: g.mergeset_order.clone(),
                    accepted: g.accepted.clone(),
                    rejected: g.rejected.clone(),
                    blue_score: g.blue_score,
                    base_blues: g.base_blues.clone(),
                    base_reds: g.base_reds.clone(),
                    window: a.window.clone(),
                    frontier: a.frontier.clone(),
                }
            })
            .collect();
        blocks.sort_by(|x, y| x.block.round.cmp(&y.block.round).then(x.block.id.cmp(&y.block.id)));
        let mut seed_rounds: Vec<(BlockId, u64)> = self.seed_rounds.iter().map(|(k, v)| (*k, *v)).collect();
        seed_rounds.sort();
        let mut seed_parents: Vec<(BlockId, Vec<BlockId>)> =
            self.seed_parents.iter().map(|(k, v)| (*k, v.clone())).collect();
        seed_parents.sort();
        let mut seed_anc: Vec<(BlockId, Vec<BlockId>, Vec<BlockId>)> = self
            .seed_anc
            .iter()
            .map(|(k, a)| (*k, a.window.clone(), a.frontier.clone()))
            .collect();
        seed_anc.sort();
        let mut pruned_children: Vec<BlockId> = self.pruned_children.iter().copied().collect();
        pruned_children.sort();
        DagState { genesis: self.genesis, blocks, seed_rounds, seed_parents, seed_anc, pruned_children }
    }

    /// Restore a DAG from `export_state` output. No re-insertion:
    /// every block's core and oracle are carried, so seed blocks
    /// (whose parents may be absent) restore exactly.
    pub fn from_state(k: u64, state: DagState) -> Dag {
        let mut d = Dag::new(k);
        d.genesis = state.genesis;
        for bs in state.blocks {
            let id = bs.block.id;
            for p in &bs.block.parents {
                d.children.entry(*p).or_default().push(id);
            }
            d.children.entry(id).or_default();
            d.ghost.insert(
                id,
                GhostCore {
                    chosen: bs.chosen,
                    mergeset_order: bs.mergeset_order,
                    accepted: bs.accepted,
                    rejected: bs.rejected,
                    blue_score: bs.blue_score,
                    base_blues: bs.base_blues,
                    base_reds: bs.base_reds,
                },
            );
            d.anc.insert(id, Anc { window: bs.window, frontier: bs.frontier });
            d.blocks.insert(id, bs.block);
        }
        d.seed_rounds = state.seed_rounds.into_iter().collect();
        d.seed_parents = state.seed_parents.into_iter().collect();
        d.seed_anc = state
            .seed_anc
            .into_iter()
            .map(|(id, window, frontier)| (id, Anc { window, frontier }))
            .collect();
        d.pruned_children = state.pruned_children.into_iter().collect();
        d
    }

    /// The GHOSTDAG total order over every block in the DAG. A pure
    /// function of the block set: two nodes holding the same blocks
    /// compute the same order regardless of insertion sequence.
    pub fn linearize(&self) -> Vec<BlockId> {
        let mut out: Vec<BlockId> = Vec::with_capacity(self.blocks.len());
        let mut seen: HashSet<BlockId> = HashSet::new();
        loop {
            // Next root: the unseen block of greatest blue score (in a
            // connected DAG the first root is the selected tip, whose
            // recursion covers everything; the loop only matters for
            // blocks no tip descends from).
            let next = self
                .blocks
                .keys()
                .filter(|&id| !seen.contains(id))
                .max_by(|a, b| {
                    self.blue_score(a)
                        .cmp(&self.blue_score(b))
                        .then(b.cmp(a))
                })
                .copied();
            let Some(root) = next else { break };
            self.append_order(root, &mut out, &mut seen);
        }
        out
    }

    fn append_order(&self, b: BlockId, out: &mut Vec<BlockId>, seen: &mut HashSet<BlockId>) {
        // Iterative post-order walk with an explicit stack. The
        // recursive original overflowed the main-thread stack on
        // Windows (1 MB) once the selected-parent chain grew long —
        // a replaying node's chain grows with its retained history,
        // so the recursion depth was unbounded (issue #1, Finding 2:
        // a node died mid-replay after closing epoch 181). This walk
        // emits exactly the recursive order: chosen subtree first,
        // then mergeset_order as listed, the block itself last;
        // `seen` is checked on entry and marked at emission, as
        // before. Equivalence is pinned by a property test against a
        // recursive reference (see the tests module).
        let mut stack: Vec<(BlockId, bool)> = vec![(b, false)];
        while let Some((id, expanded)) = stack.pop() {
            if expanded {
                seen.insert(id);
                out.push(id);
                continue;
            }
            if seen.contains(&id) {
                continue;
            }
            let g = &self.ghost[&id];
            stack.push((id, true));
            // LIFO: push children in reverse processing order — the
            // mergeset entries reversed, then the chosen parent on
            // top so its subtree is processed first.
            for x in g.mergeset_order.iter().rev() {
                stack.push((*x, false));
            }
            if let Some(c) = g.chosen {
                stack.push((c, false));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blk(machine: u64, round: u64, parents: Vec<BlockId>, tag: u8) -> Block {
        Block::new(machine, round, parents, vec![tag])
    }

    #[test]
    fn chain_orders_as_a_chain() {
        let mut d = Dag::new(3);
        let g = blk(1, 0, vec![], 0);
        let gid = g.id;
        d.insert(g).unwrap();
        let mut prev = gid;
        let mut ids = vec![gid];
        for r in 1..6 {
            let b = blk(1, r, vec![prev], r as u8);
            prev = b.id;
            ids.push(b.id);
            d.insert(b).unwrap();
        }
        assert_eq!(d.linearize(), ids);
        assert_eq!(d.blue_score(&prev), 5);
        assert_eq!(d.selected_tip(), Some(prev));
    }

    #[test]
    fn parallel_blocks_join_blue_within_k() {
        let mut d = Dag::new(3);
        let g = blk(1, 0, vec![], 0);
        let gid = g.id;
        d.insert(g).unwrap();
        let a = blk(1, 1, vec![gid], 1);
        let b = blk(2, 1, vec![gid], 2);
        let (aid, bid) = (a.id, b.id);
        d.insert(a).unwrap();
        d.insert(b).unwrap();
        let m = blk(3, 2, vec![aid, bid], 3);
        let mid = m.id;
        d.insert(m).unwrap();
        let gd = d.ghost(&mid).unwrap();
        assert!(gd.blues.contains(&aid) && gd.blues.contains(&bid), "both parents blue at k=3");
        assert_eq!(gd.blue_score, 3); // genesis + both parents

        // At k = 0 the second parent must turn red: exactly one block of
        // its past (the other parent) sits in its anticone.
        let mut d0 = Dag::new(0);
        d0.insert(blk(1, 0, vec![], 0)).unwrap();
        // Rebuild with the same ids: blocks are content-addressed.
        let g0 = blk(1, 0, vec![], 0);
        assert_eq!(g0.id, gid);
        d0.insert(blk(1, 1, vec![gid], 1)).unwrap();
        d0.insert(blk(2, 1, vec![gid], 2)).unwrap();
        let m0 = blk(3, 2, vec![aid, bid], 3);
        d0.insert(m0).unwrap();
        let gd0 = d0.ghost(&mid).unwrap();
        assert_eq!(gd0.reds.len(), 1);
        assert_eq!(gd0.blue_score, 2);
    }

    #[test]
    fn linearization_is_insertion_order_independent() {
        // A deterministic 60-block DAG: each block takes up to 3 current
        // tips as parents.
        let mut gen = Dag::new(3);
        let g = blk(1, 0, vec![], 0);
        gen.insert(g.clone()).unwrap();
        let mut all = vec![g];
        for r in 1..60u64 {
            let mut parents = gen.tips();
            parents.truncate(3);
            let b = blk(r % 7 + 1, r, parents, (r * 31 % 251) as u8);
            gen.insert(b.clone()).unwrap();
            all.push(b);
        }
        let want_order = gen.linearize();
        assert_eq!(want_order.len(), 60);

        // A second DAG receiving the same blocks in a different valid
        // order (same rounds, descending id within the round).
        let mut other = Dag::new(3);
        let mut by_round: Vec<Vec<Block>> = vec![Vec::new(); 60];
        for b in &all {
            by_round[b.round as usize].push(b.clone());
        }
        for round in by_round.iter_mut() {
            round.sort_by(|a, b| b.id.cmp(&a.id));
            for b in round {
                other.insert(b.clone()).unwrap();
            }
        }
        assert_eq!(other.linearize(), want_order, "GHOSTDAG order must not depend on arrival order");
        for b in &all {
            assert_eq!(other.blue_score(&b.id), gen.blue_score(&b.id), "blue scores must agree");
        }
    }

    /// The pre-redesign recursive append_order, kept as the reference
    /// the iterative walk must match EXACTLY (same emission order) on
    /// every DAG shape. Reads the stored rope cores directly.
    fn reference_append(d: &Dag, b: BlockId, out: &mut Vec<BlockId>, seen: &mut HashSet<BlockId>) {
        if seen.contains(&b) {
            return;
        }
        let g = &d.ghost[&b];
        if let Some(c) = g.chosen {
            reference_append(d, c, out, seen);
        }
        for x in &g.mergeset_order {
            reference_append(d, *x, out, seen);
        }
        seen.insert(b);
        out.push(b);
    }

    fn reference_linearize(d: &Dag) -> Vec<BlockId> {
        let mut out: Vec<BlockId> = Vec::new();
        let mut seen: HashSet<BlockId> = HashSet::new();
        loop {
            let next = d
                .blocks
                .keys()
                .filter(|&id| !seen.contains(id))
                .max_by(|a, b| d.blue_score(a).cmp(&d.blue_score(b)).then(b.cmp(a)))
                .copied();
            let Some(root) = next else { break };
            reference_append(d, root, &mut out, &mut seen);
        }
        out
    }

    /// Property test: the iterative append_order produces the
    /// recursive original's order on many pseudo-random DAG shapes
    /// (forks, merges, diamonds — the shapes where a stack-based
    /// walk most easily diverges from recursion).
    #[test]
    fn iterative_order_matches_recursive_reference() {
        // xorshift64* — deterministic, no dependencies.
        let mut state = 0x9E3779B97F4A7C15u64;
        let mut next = move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545F4914F6CDD1D)
        };
        for trial in 0..24 {
            let mut d = Dag::new(3);
            let g = blk(1, 0, vec![], 0);
            let gid = g.id;
            d.insert(g).unwrap();
            let mut ids = vec![gid];
            let n = 40 + (next() % 80);
            for r in 1..n {
                // 1..=3 distinct parents sampled from earlier blocks.
                let want = 1 + (next() % 3) as usize;
                let mut parents: Vec<BlockId> = Vec::new();
                let mut guard = 0;
                while parents.len() < want && guard < 16 {
                    guard += 1;
                    let cand = ids[(next() as usize) % ids.len()];
                    if !parents.contains(&cand) {
                        parents.push(cand);
                    }
                }
                let b = blk((r % 5) + 1, r, parents, (r % 251) as u8);
                ids.push(b.id);
                d.insert(b).unwrap();
            }
            assert_eq!(
                d.linearize(),
                reference_linearize(&d),
                "iterative order diverged from the recursive reference on trial {trial}"
            );
        }
    }

    /// Regression test for issue #1 Finding 2 (Windows stack
    /// overflow): linearize a 4,000-deep selected-parent chain on a
    /// thread with a 256 KB stack — far below what the recursive
    /// walk needed per thousand blocks on a 1 MB main thread. The
    /// iterative walk's own stack use is O(1) frames; its work list
    /// lives on the heap.
    #[test]
    fn deep_chain_linearizes_on_a_small_stack() {
        let handle = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| {
                let mut d = Dag::new(3);
                let g = blk(1, 0, vec![], 0);
                let mut prev = g.id;
                let mut ids = vec![g.id];
                d.insert(g).unwrap();
                for r in 1..4000u64 {
                    let b = blk(1, r, vec![prev], (r % 251) as u8);
                    prev = b.id;
                    ids.push(b.id);
                    d.insert(b).unwrap();
                }
                let order = d.linearize();
                assert_eq!(order, ids, "a chain must order as the chain");
            })
            .unwrap();
        handle.join().unwrap();
    }

    /// The ancestor oracle must stay exact far beyond the window:
    /// on a long chain every earlier block is an ancestor of every
    /// later one, and retained window/frontier sizes stay bounded.
    #[test]
    fn ancestor_oracle_exact_beyond_the_window() {
        let mut d = Dag::new(3);
        let g = blk(1, 0, vec![], 0);
        let mut prev = g.id;
        let mut ids = vec![g.id];
        d.insert(g).unwrap();
        for r in 1..600u64 {
            let b = blk(1, r, vec![prev], (r % 251) as u8);
            prev = b.id;
            ids.push(b.id);
            d.insert(b).unwrap();
        }
        let tip = *ids.last().unwrap();
        for (i, id) in ids.iter().enumerate() {
            assert!(d.is_ancestor(id, &tip), "chain block {i} must be an ancestor of the tip");
            let a = &d.anc[id];
            assert!(
                a.window.len() <= (WINDOW_ROUNDS as usize) + 1,
                "window must stay bounded, got {} at round {i}",
                a.window.len()
            );
            assert!(a.frontier.len() <= 1, "chain frontier is a single cut block, got {}", a.frontier.len());
        }
        // Non-ancestry across the chain: nothing is an ancestor of genesis.
        for id in &ids[1..] {
            assert!(!d.is_ancestor(id, &ids[0]));
        }
    }

    /// Retained oracle data stays bounded on a wide mesh too: window is
    /// at most WINDOW_ROUNDS rounds of width, frontier at most a band
    /// of boundary parents.
    #[test]
    fn oracle_data_bounded_on_a_wide_mesh() {
        let width = 6u64;
        let rounds = 300u64;
        let mut d = Dag::new(3);
        let g = blk(1, 0, vec![], 0);
        let gid = g.id;
        d.insert(g).unwrap();
        let mut prev_round: Vec<BlockId> = vec![gid];
        for r in 1..rounds {
            let mut this_round = Vec::new();
            for m in 0..width {
                // Each block takes two parents from the previous round.
                let p1 = prev_round[(m as usize) % prev_round.len()];
                let p2 = prev_round[((m as usize) + 1) % prev_round.len()];
                let mut parents = vec![p1];
                if p2 != p1 {
                    parents.push(p2);
                }
                let b = blk(m + 1, r, parents, (r % 251) as u8);
                this_round.push(b.id);
                d.insert(b).unwrap();
            }
            prev_round = this_round;
        }
        let max_window = (WINDOW_ROUNDS as usize + 1) * (width as usize);
        for (id, a) in &d.anc {
            assert!(a.window.len() <= max_window, "window {} exceeds bound at {:?}", a.window.len(), id);
            assert!(
                a.frontier.len() <= 2 * (width as usize),
                "frontier {} exceeds bound at {:?}",
                a.frontier.len(),
                id
            );
        }
    }
}

// -- Wire encoding (the gossip payload format for blocks) -------------------

/// Canonical block encoding: machine, round, parents, payload, id —
/// big-endian counts and lengths throughout, mirroring poe-store's style.
pub fn encode_block(b: &Block) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + b.parents.len() * 64 + b.payload.len());
    out.extend_from_slice(&b.machine.to_be_bytes());
    out.extend_from_slice(&b.round.to_be_bytes());
    out.extend_from_slice(&(b.parents.len() as u32).to_be_bytes());
    for p in &b.parents {
        out.extend_from_slice(p);
    }
    out.extend_from_slice(&(b.payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&b.payload);
    out.extend_from_slice(&b.id);
    out
}

/// Decode a block; the id is recomputed from the fields and must match
/// the carried id, so a tampered payload never decodes.
pub fn decode_block(raw: &[u8]) -> Option<Block> {
    let mut off = 0usize;
    let take = |raw: &[u8], off: &mut usize, n: usize| -> Option<Vec<u8>> {
        let end = off.checked_add(n)?;
        let s = raw.get(*off..end)?.to_vec();
        *off = end;
        Some(s)
    };
    let machine = u64::from_be_bytes(take(raw, &mut off, 8)?.try_into().ok()?);
    let round = u64::from_be_bytes(take(raw, &mut off, 8)?.try_into().ok()?);
    let np = u32::from_be_bytes(take(raw, &mut off, 4)?.try_into().ok()?) as usize;
    if np > 1024 {
        return None;
    }
    let mut parents = Vec::with_capacity(np);
    for _ in 0..np {
        let p: BlockId = take(raw, &mut off, 64)?.try_into().ok()?;
        parents.push(p);
    }
    let plen = u32::from_be_bytes(take(raw, &mut off, 4)?.try_into().ok()?) as usize;
    if plen > 1 << 22 {
        return None;
    }
    let payload = take(raw, &mut off, plen)?;
    let id: BlockId = take(raw, &mut off, 64)?.try_into().ok()?;
    let b = Block::new(machine, round, parents, payload);
    if b.id != id {
        return None;
    }
    Some(b)
}

impl Dag {
    /// Every block in the DAG, in a deterministic order (round, then id) —
    /// what a state snapshot serializes and a restoring node replays.
    pub fn blocks(&self) -> Vec<Block> {
        let mut bs: Vec<Block> = self.blocks.values().cloned().collect();
        bs.sort_by(|a, b| a.round.cmp(&b.round).then(a.id.cmp(&b.id)));
        bs
    }
}
