//! Seed-aware snapshot restore (2026-11-16): a Finality whose DAG
//! has been pruned must snapshot and restore EXACTLY — the state
//! path carries every retained block's core and oracle plus the
//! compaction seeds. The legacy blocks-only path demonstrably
//! cannot: the anchor block's parent is pruned away, re-insertion
//! drops the anchor, and its whole descendant cone goes with it.
//! This test pins both halves of that statement.

use poe_dag::{Block, BlockId};
use poe_finality::Finality;

fn blk(machine: u64, round: u64, parents: Vec<BlockId>, tag: u8) -> Block {
    Block::new(machine, round, parents, vec![tag])
}

fn build_finality() -> (Finality, Vec<BlockId>) {
    let mut fin = Finality::new(3, 16);
    let g = blk(1, 0, vec![], 0);
    let gid = g.id;
    fin.dag.insert(g).unwrap();
    let mut ids = vec![gid];
    for r in 1..80u64 {
        for m in 0..3u64 {
            let parents = fin.dag.tips();
            let b = blk(m + 1, r, parents, (r % 251) as u8);
            ids.push(b.id);
            fin.dag.insert(b).unwrap();
        }
        // Mark the round's first block finalized, as the live
        // finality engine would have done by the epoch close.
        let first = fin.dag.blocks().into_iter().find(|b| b.round == r).unwrap();
        fin.finalized.insert(r, first.id);
    }
    (fin, ids)
}

fn chain_anchor(fin: &Finality, round: u64) -> BlockId {
    let mut cur = fin.dag.selected_tip().expect("tip");
    loop {
        let g = fin.dag.ghost(&cur).expect("ghost");
        if fin.dag.get(&cur).map(|b| b.round).unwrap_or(0) <= round {
            return cur;
        }
        cur = g.chosen.expect("chain continues");
    }
}

#[test]
fn pruned_finality_snapshots_and_restores_exactly() {
    let (mut fin, _ids) = build_finality();
    let anchor = chain_anchor(&fin, 32);
    let dropped = fin.dag.prune(&anchor);
    assert!(dropped > 0, "the mesh must actually prune");
    let retained = fin.dag.blocks().len();

    // State-carrying snapshot: exact restore.
    let snap = fin.snapshot();
    assert!(snap.dag_state.is_some(), "snapshot() must carry the DAG state");
    let restored = Finality::restore(snap);
    assert_eq!(restored.dag.blocks().len(), retained, "state restore must keep every retained block");
    assert_eq!(restored.dag.selected_tip(), fin.dag.selected_tip());
    assert_eq!(restored.finalized, fin.finalized);
    for b in fin.dag.blocks() {
        assert_eq!(restored.dag.blue_score(&b.id), fin.dag.blue_score(&b.id));
        assert_eq!(
            restored.dag.ghost(&b.id).unwrap().blues,
            fin.dag.ghost(&b.id).unwrap().blues,
            "restored blues diverged at {:?}",
            b.id
        );
    }

    // The full (finstate) snapshot path restores exactly too.
    let restored_full = Finality::restore_full(fin.snapshot_full());
    assert_eq!(restored_full.dag.blocks().len(), retained);
    assert_eq!(restored_full.dag.selected_tip(), fin.dag.selected_tip());

    // The legacy blocks-only path loses the anchor's cone: the
    // anchor's parent was pruned, so re-insertion drops the anchor
    // and everything descending from it. This is the failure the
    // seed-aware path exists to prevent — pinned here so the two
    // paths can never silently swap.
    let mut legacy_snap = fin.snapshot();
    legacy_snap.dag_state = None;
    let legacy = Finality::restore(legacy_snap);
    assert!(
        legacy.dag.get(&anchor).is_none(),
        "legacy restore must (demonstrably) lose the anchor whose parent was pruned"
    );
    assert!(legacy.dag.blocks().len() < retained);
}
