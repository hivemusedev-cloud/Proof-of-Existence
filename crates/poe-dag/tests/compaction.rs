//! The compaction replay gate (PROPOSAL_LIVENESS_AND_DAG_STORAGE.md
//! §2): two DAGs receive the identical block stream; one prunes at
//! every epoch boundary, the other never does. After every prune and
//! at the end, the pruned DAG must answer identically to the full
//! one on everything the future can still ask:
//!   * the selected tip and the tip set;
//!   * blue score and ghost data (blues / reds / mergeset order) of
//!     every retained block — byte-identical, via the cut blocks'
//!     materialized base lists;
//!   * ancestry INTO every retained block, for retained and pruned
//!     candidate ids alike (the seed paths);
//!   * the ghost data of every block inserted AFTER pruning began
//!     (future inserts are where a subtle compaction would fork the
//!     network — this is the strong assertion);
//!   * the vote target of every round above the last anchor: the
//!     first block of that round in linearization order.
//! Shapes are fork-heavy: a wide mesh whose proposals take all
//! current tips (as the node does), plus a long-lived fork that
//! diverges early, runs parallel for tens of rounds, and merges
//! back — the shape the exactness analysis was about.

use poe_dag::{Block, BlockId, Dag};

fn blk(machine: u64, round: u64, parents: Vec<BlockId>, tag: u8) -> Block {
    Block::new(machine, round, parents, vec![tag])
}

/// xorshift64* — deterministic, no dependencies.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

/// The block on `dag`'s selected chain at or just below `round`:
/// walk chosen links down from the selected tip.
fn chain_anchor(dag: &Dag, round: u64) -> BlockId {
    let mut cur = dag.selected_tip().expect("tip");
    loop {
        let g = dag.ghost(&cur).expect("ghost");
        if dag.get(&cur).map(|b| b.round).unwrap_or(0) <= round {
            return cur;
        }
        cur = g.chosen.expect("chain continues below the boundary");
    }
}

fn assert_same_answers(full: &Dag, pruned: &Dag, all_ids: &[BlockId], context: &str) {
    assert_eq!(full.selected_tip(), pruned.selected_tip(), "selected tip diverged: {context}");
    let mut ft = full.tips();
    let mut pt = pruned.tips();
    ft.sort();
    pt.sort();
    assert_eq!(ft, pt, "tip set diverged: {context}");
    let retained: Vec<BlockId> = pruned.blocks().iter().map(|b| b.id).collect();
    let retained_set: std::collections::HashSet<BlockId> = retained.iter().copied().collect();
    for id in &retained {
        assert_eq!(full.blue_score(id), pruned.blue_score(id), "blue score diverged at {id:?}: {context}");
        let fg = full.ghost(id).expect("full ghost");
        let pg = pruned.ghost(id).expect("pruned ghost");
        assert_eq!(fg.blues, pg.blues, "blues diverged at {id:?}: {context}");
        assert_eq!(fg.reds, pg.reds, "reds diverged at {id:?}: {context}");
        assert_eq!(fg.mergeset_order, pg.mergeset_order, "mergeset diverged at {id:?}: {context}");
        assert_eq!(fg.blue_score, pg.blue_score, "ghost score diverged at {id:?}: {context}");
        if let Some(c) = pg.chosen {
            assert_eq!(fg.chosen, Some(c), "chosen diverged at {id:?}: {context}");
        }
        // Ancestry into this retained block, from every block ever
        // inserted (retained or pruned) — the seed paths must answer
        // exactly as the full DAG does.
        for x in all_ids {
            assert_eq!(
                full.is_ancestor(x, id),
                pruned.is_ancestor(x, id),
                "is_ancestor({x:?}, {id:?}) diverged: {context}"
            );
        }
    }
    let _ = retained_set;
}

#[test]
fn compaction_replay_gate_fork_heavy_mesh() {
    let width = 4u64;
    let rounds = 128u64;
    let rpe = 16u64; // "epoch" length for anchor cadence
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let mut full = Dag::new(3);
    let mut pruned = Dag::new(3);
    let g = blk(1, 0, vec![], 0);
    let gid = g.id;
    full.insert(g.clone()).unwrap();
    pruned.insert(g).unwrap();
    let mut all_ids: Vec<BlockId> = vec![gid];
    let mut total_dropped = 0usize;
    // The long-lived fork: diverges at round 20 from the main mesh,
    // runs on its own tip until round 70, then merges back.
    let mut fork_tip: Option<BlockId> = None;

    for r in 1..rounds {
        let mut new_blocks: Vec<Block> = Vec::new();
        if r == 20 {
            // Fork genesis: a block whose only parent is a main tip.
            let parents = vec![full.tips()[0]];
            let b = blk(99, r, parents, 200);
            fork_tip = Some(b.id);
            new_blocks.push(b);
        } else if (21..70).contains(&r) {
            // The fork advances on its own lineage only.
            let b = blk(99, r, vec![fork_tip.unwrap()], (200 + (r % 50)) as u8);
            fork_tip = Some(b.id);
            new_blocks.push(b);
        }
        for m in 0..width {
            // Node-like proposals: parents = all current tips (which
            // consumes the fork tip too, once it exists) — except in
            // the fork's parallel window, where main proposals take
            // only main tips so the fork stays genuinely separate
            // until its merge round.
            let mut parents = full.tips();
            if (21..70).contains(&r) {
                parents.retain(|p| Some(*p) != fork_tip);
            }
            if r == 70 {
                // Merge: the fork tip joins the parent set for good.
                if let Some(ft) = fork_tip {
                    if !parents.contains(&ft) {
                        parents.push(ft);
                    }
                }
            }
            // Occasionally drop a random parent to vary the shape.
            if parents.len() > 2 && rng.next() % 5 == 0 {
                parents.remove((rng.next() as usize) % parents.len());
            }
            let b = blk(m + 1, r, parents, (r % 251) as u8);
            new_blocks.push(b);
        }
        for b in new_blocks {
            all_ids.push(b.id);
            full.insert(b.clone()).unwrap();
            let pg = pruned.insert(b.clone());
            assert!(pg.is_ok(), "pruned insert failed at round {r}: {pg:?}");
            // Future-insert identity, checked from the first prune on.
            if total_dropped > 0 {
                let fg = full.ghost(&b.id).unwrap();
                let pg = pruned.ghost(&b.id).unwrap();
                assert_eq!(fg.blues, pg.blues, "post-prune insert blues diverged at round {r}");
                assert_eq!(fg.reds, pg.reds, "post-prune insert reds diverged at round {r}");
                assert_eq!(fg.mergeset_order, pg.mergeset_order, "post-prune mergeset diverged at round {r}");
                assert_eq!(fg.chosen, pg.chosen, "post-prune chosen diverged at round {r}");
                assert_eq!(fg.blue_score, pg.blue_score, "post-prune score diverged at round {r}");
            }
        }
        // Epoch boundary: prune the second DAG at the chain block of
        // the epoch that closed two epochs ago.
        if r % rpe == rpe - 1 && r >= 2 * rpe {
            let boundary = r + 1 - 2 * rpe;
            let anchor = chain_anchor(&full, boundary);
            let dropped_now = pruned.prune(&anchor);
            total_dropped += dropped_now;
            if dropped_now > 0 {
                assert_same_answers(&full, &pruned, &all_ids, &format!("after prune at round {r}"));
                // Vote-target identity for every round above the anchor.
                let fo = full.linearize();
                let po = pruned.linearize();
                for vr in (boundary + 1)..r {
                    let f = fo.iter().find(|id| full.get(id).map(|b| b.round) == Some(vr));
                    let p = po.iter().find(|id| pruned.get(id).map(|b| b.round) == Some(vr));
                    assert_eq!(f, p, "vote target diverged for round {vr}");
                }
            }
        }
    }
    assert!(total_dropped > 0, "pruning never dropped anything on a fork-heavy mesh");
    assert!(
        pruned.blocks().len() < full.blocks().len(),
        "pruned DAG must retain fewer blocks ({} vs {})",
        pruned.blocks().len(),
        full.blocks().len()
    );
    assert_same_answers(&full, &pruned, &all_ids, "final");

    // State round trip: the pruned DAG's exported state restores
    // exactly, and the restored DAG keeps answering identically —
    // including for the next block inserted into both.
    let restored = Dag::from_state(3, pruned.export_state());
    assert_same_answers(&full, &restored, &all_ids, "restored-from-state");
    let parents = restored.tips();
    let nb = blk(7, rounds, parents, 42);
    let mut restored2 = Dag::from_state(3, pruned.export_state());
    restored2.insert(nb.clone()).unwrap();
    let mut pruned2 = Dag::from_state(3, pruned.export_state());
    pruned2.insert(nb.clone()).unwrap();
    let rg = restored2.ghost(&nb.id).unwrap();
    let pg = pruned2.ghost(&nb.id).unwrap();
    assert_eq!(rg.blues, pg.blues, "restored DAG's next insert blues diverged");
    assert_eq!(rg.blue_score, pg.blue_score, "restored DAG's next insert score diverged");
}

#[test]
fn prune_refuses_when_a_tip_does_not_descend_from_the_anchor() {
    // A fork that diverges and never merges: its tip is not a
    // descendant of a main-chain anchor, so the anchor is not a
    // pruning point and prune must refuse (drop nothing).
    let mut d = Dag::new(3);
    let g = blk(1, 0, vec![], 0);
    let gid = g.id;
    d.insert(g).unwrap();
    let mut main = gid;
    let mut fork = gid;
    for r in 1..40u64 {
        let b = blk(1, r, vec![main], (r % 251) as u8);
        main = b.id;
        d.insert(b).unwrap();
        let f = blk(2, r, vec![fork], (r % 251) as u8);
        fork = f.id;
        d.insert(f).unwrap();
    }
    let before = d.blocks().len();
    // Anchor deep in the main chain: the fork tip does not descend
    // from it (the fork diverged at genesis).
    let anchor = chain_anchor(&d, 20);
    assert_eq!(d.prune(&anchor), 0, "prune must refuse a non-pruning-point anchor");
    assert_eq!(d.blocks().len(), before, "a refused prune must not change the DAG");
    // The genesis anchor is a pruning point (ancestor of every tip)
    // but has no strict ancestors: still nothing to drop.
    assert_eq!(d.prune(&gid), 0);
    assert_eq!(d.blocks().len(), before);
}

#[test]
fn prune_on_a_chain_materializes_the_prefix() {
    // The pure chain: no mergeset references at all, so the whole
    // prefix below the anchor is droppable and the anchor's base
    // lists must carry it exactly.
    let mut full = Dag::new(3);
    let mut pruned = Dag::new(3);
    let g = blk(1, 0, vec![], 0);
    let mut prev = g.id;
    let mut ids = vec![g.id];
    full.insert(g.clone()).unwrap();
    pruned.insert(g).unwrap();
    for r in 1..300u64 {
        let b = blk(1, r, vec![prev], (r % 251) as u8);
        prev = b.id;
        ids.push(b.id);
        full.insert(b.clone()).unwrap();
        pruned.insert(b).unwrap();
    }
    let anchor = ids[150];
    let dropped = pruned.prune(&anchor);
    assert_eq!(dropped, 150, "the whole strict prefix of a chain is droppable");
    assert_eq!(pruned.blocks().len(), 150);
    let tip = ids[299];
    assert_eq!(full.blue_score(&tip), pruned.blue_score(&tip));
    assert_eq!(full.ghost(&tip).unwrap().blues, pruned.ghost(&tip).unwrap().blues);
    assert_eq!(full.ghost(&anchor).unwrap().blues, pruned.ghost(&anchor).unwrap().blues);
    assert!(pruned.is_ancestor(&ids[0], &tip), "genesis must still answer as an ancestor via the seeds");
    assert!(pruned.is_ancestor(&ids[149], &tip));
    assert!(!pruned.is_ancestor(&tip, &ids[0]));
    assert_eq!(full.selected_tip(), pruned.selected_tip());
    assert_eq!(full.tips(), pruned.tips());
    // And the pruned chain keeps growing identically.
    let nb = blk(1, 300, vec![tip], 7);
    full.insert(nb.clone()).unwrap();
    pruned.insert(nb.clone()).unwrap();
    assert_eq!(full.ghost(&nb.id).unwrap().blues, pruned.ghost(&nb.id).unwrap().blues);
    assert_eq!(full.blue_score(&nb.id), pruned.blue_score(&nb.id));
}
