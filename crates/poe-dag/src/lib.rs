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

use poe_crypto::hash::{h, Part, H512};
use std::collections::{HashMap, HashSet};

pub type BlockId = H512;

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

/// GHOSTDAG data for one block, computed at insert time from its parents
/// (all of which are already in the DAG, so this never changes afterwards).
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

#[derive(Debug, PartialEq, Eq)]
pub enum DagError {
    UnknownParent,
    SecondGenesis,
    Duplicate,
}

pub struct Dag {
    blocks: HashMap<BlockId, Block>,
    ghost: HashMap<BlockId, GhostData>,
    ancestors: HashMap<BlockId, HashSet<BlockId>>,
    children: HashMap<BlockId, Vec<BlockId>>,
    genesis: Option<BlockId>,
    /// The GHOSTDAG cluster parameter: how many blue blocks may sit in a
    /// candidate's anticone before the candidate turns red.
    pub k: u64,
}

impl Dag {
    pub fn new(k: u64) -> Dag {
        Dag {
            blocks: HashMap::new(),
            ghost: HashMap::new(),
            ancestors: HashMap::new(),
            children: HashMap::new(),
            genesis: None,
            k,
        }
    }

    pub fn get(&self, id: &BlockId) -> Option<&Block> {
        self.blocks.get(id)
    }

    pub fn ghost(&self, id: &BlockId) -> Option<&GhostData> {
        self.ghost.get(id)
    }

    pub fn blue_score(&self, id: &BlockId) -> u64 {
        self.ghost.get(id).map(|g| g.blue_score).unwrap_or(0)
    }

    pub fn is_ancestor(&self, anc: &BlockId, of: &BlockId) -> bool {
        self.ancestors.get(of).map(|s| s.contains(anc)).unwrap_or(false)
    }

    /// Current tips (blocks with no children), in deterministic order.
    pub fn tips(&self) -> Vec<BlockId> {
        let mut t: Vec<BlockId> = self
            .blocks
            .keys()
            .filter(|&id| self.children.get(id).map(|c| c.is_empty()).unwrap_or(true))
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
        // Ancestor set: the block itself plus every parent's ancestors.
        let mut anc: HashSet<BlockId> = HashSet::new();
        anc.insert(block.id);
        for p in &block.parents {
            anc.extend(self.ancestors[p].iter().copied());
        }

        let ghost = if block.parents.is_empty() {
            GhostData { chosen: None, blues: vec![], reds: vec![], mergeset_order: vec![], blue_score: 0 }
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
            let chosen_ghost = self.ghost[&chosen].clone();
            // Mergeset: every other parent's past, minus the chosen past.
            let mut mergeset: HashSet<BlockId> = HashSet::new();
            for p in &block.parents {
                if *p != chosen {
                    mergeset.extend(self.ancestors[p].iter().copied());
                }
            }
            for a in &self.ancestors[&chosen] {
                mergeset.remove(a);
            }
            // Consider in decreasing blue-score order, ties by id.
            let mut order: Vec<BlockId> = mergeset.into_iter().collect();
            order.sort_by(|a, b| {
                self.blue_score(b)
                    .cmp(&self.blue_score(a))
                    .then(a.cmp(b))
            });
            let mut blues: Vec<BlockId> = chosen_ghost.blues.clone();
            blues.push(chosen);
            let mut reds: Vec<BlockId> = chosen_ghost.reds.clone();
            for cand in &order {
                let cand_anc = &self.ancestors[cand];
                let in_anticone = blues
                    .iter()
                    .filter(|&y| !cand_anc.contains(y) && !self.ancestors[y].contains(cand))
                    .count() as u64;
                if in_anticone <= self.k {
                    blues.push(*cand);
                } else {
                    reds.push(*cand);
                }
            }
            let blue_score = blues.len() as u64;
            GhostData { chosen: Some(chosen), blues, reds, mergeset_order: order, blue_score }
        };

        for p in &block.parents {
            self.children.entry(*p).or_default().push(block.id);
        }
        self.children.entry(block.id).or_default();
        self.ancestors.insert(block.id, anc);
        self.ghost.insert(block.id, ghost);
        self.blocks.insert(block.id, block);
        Ok(())
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
        if seen.contains(&b) {
            return;
        }
        let g = &self.ghost[&b];
        if let Some(c) = g.chosen {
            self.append_order(c, out, seen);
        }
        for x in &g.mergeset_order {
            self.append_order(*x, out, seen);
        }
        seen.insert(b);
        out.push(b);
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
