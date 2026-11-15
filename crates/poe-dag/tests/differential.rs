//! Differential battery: the bounded-memory `Dag` (2026-11-15 redesign)
//! against a verbatim copy of the original full-set implementation
//! (`old_dag.rs`, renamed `OldDag`). The redesign is only correct if
//! every observable answer is identical: linearization, blue scores,
//! ghost blues/reds/mergeset order, selected tip, and `is_ancestor`
//! for every pair — including pairs far beyond the ancestor window.

mod old_dag;

use old_dag::OldDag;
use poe_dag::{Block, BlockId, Dag};

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state >> 12;
    *state ^= *state << 25;
    *state ^= *state >> 27;
    state.wrapping_mul(0x2545F4914F6CDD1D)
}

fn insert_both(new: &mut Dag, old: &mut OldDag, machine: u64, round: u64, parents: Vec<BlockId>, tag: u8) -> BlockId {
    let b = Block::new(machine, round, parents.clone(), vec![tag]);
    let ob = old_dag::Block::new(machine, round, parents, vec![tag]);
    assert_eq!(b.id, ob.id, "content addressing must agree");
    let id = b.id;
    new.insert(b).unwrap();
    old.insert(ob).unwrap();
    id
}

fn assert_same(new: &Dag, old: &OldDag, ids: &[BlockId], all_pairs: bool) {
    assert_eq!(new.linearize(), old.linearize(), "linearization diverged");
    assert_eq!(new.selected_tip(), old.selected_tip(), "selected tip diverged");
    for id in ids {
        assert_eq!(new.blue_score(id), old.blue_score(id), "blue score diverged at {id:?}");
        let g = new.ghost(id).unwrap();
        let og = old.ghost(id).unwrap();
        assert_eq!(g.chosen, og.chosen, "chosen diverged at {id:?}");
        assert_eq!(g.blues, og.blues, "blues diverged at {id:?}");
        assert_eq!(g.reds, og.reds, "reds diverged at {id:?}");
        assert_eq!(g.mergeset_order, og.mergeset_order, "mergeset order diverged at {id:?}");
    }
    if all_pairs {
        for a in ids {
            for b in ids {
                assert_eq!(
                    new.is_ancestor(a, b),
                    old.is_ancestor(a, b),
                    "is_ancestor({a:?}, {b:?}) diverged"
                );
            }
        }
    }
}

#[test]
fn differential_random_dags() {
    let mut state = 0x12345678ABCDEF01u64;
    for trial in 0..16 {
        let k = (trial % 4) as u64; // exercise k = 0..=3
        let mut new = Dag::new(k);
        let mut old = OldDag::new(k);
        let gid = insert_both(&mut new, &mut old, 1, 0, vec![], 0);
        let mut ids = vec![gid];
        let n = 30 + (xorshift(&mut state) % 50);
        for r in 1..n {
            let want = 1 + (xorshift(&mut state) % 3) as usize;
            let mut parents: Vec<BlockId> = Vec::new();
            let mut guard = 0;
            while parents.len() < want && guard < 16 {
                guard += 1;
                let cand = ids[(xorshift(&mut state) as usize) % ids.len()];
                if !parents.contains(&cand) {
                    parents.push(cand);
                }
            }
            let id = insert_both(&mut new, &mut old, (r % 5) + 1, r, parents, (r % 251) as u8);
            ids.push(id);
        }
        assert_same(&new, &old, &ids, true);
    }
}

#[test]
fn differential_wide_mesh_beyond_window() {
    // 6-wide mesh, 300 rounds: ancestor relations span ~10 windows.
    let width = 6u64;
    let rounds = 300u64;
    let mut new = Dag::new(3);
    let mut old = OldDag::new(3);
    let gid = insert_both(&mut new, &mut old, 1, 0, vec![], 0);
    let mut ids = vec![gid];
    let mut prev_round: Vec<BlockId> = vec![gid];
    for r in 1..rounds {
        let mut this_round = Vec::new();
        for m in 0..width {
            let p1 = prev_round[(m as usize) % prev_round.len()];
            let p2 = prev_round[((m as usize) + 1) % prev_round.len()];
            let mut parents = vec![p1];
            if p2 != p1 {
                parents.push(p2);
            }
            let id = insert_both(&mut new, &mut old, m + 1, r, parents, (r % 251) as u8);
            this_round.push(id);
            ids.push(id);
        }
        prev_round = this_round;
    }
    // All-pairs on a sample (full all-pairs is 1800^2 oracle calls on
    // the old side too — sample the tip's relations and a stride).
    assert_same(&new, &old, &ids, false);
    let tip = new.selected_tip().unwrap();
    for id in &ids {
        assert_eq!(new.is_ancestor(id, &tip), old.is_ancestor(id, &tip), "tip ancestry diverged at {id:?}");
    }
    for (i, a) in ids.iter().step_by(37).enumerate() {
        for b in ids.iter().step_by(41).skip(i % 5) {
            assert_eq!(new.is_ancestor(a, b), old.is_ancestor(a, b), "sampled ancestry diverged");
        }
    }
}

#[test]
fn differential_long_chain() {
    let mut new = Dag::new(3);
    let mut old = OldDag::new(3);
    let gid = insert_both(&mut new, &mut old, 1, 0, vec![], 0);
    let mut ids = vec![gid];
    let mut prev = gid;
    for r in 1..2000u64 {
        let id = insert_both(&mut new, &mut old, 1, r, vec![prev], (r % 251) as u8);
        ids.push(id);
        prev = id;
    }
    assert_same(&new, &old, &ids, false);
    for id in &ids {
        assert!(new.is_ancestor(id, &prev));
    }
}
