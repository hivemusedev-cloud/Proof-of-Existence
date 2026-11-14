//! Step 12b — the simnet at scale: 100 machines (the Step 4 finish
//! line used 10), 30% Byzantine — twenty double-proposers, ten vote
//! equivocators — committees drawn from the full registry, 48 rounds
//! (three epochs of 16) with votes delivered two rounds late.
//!
//! Expected, as at the finish line: every Byzantine act surfaces as
//! evidence and revocation, exactly one block finalizes per round,
//! every round finalizes despite the delay, and two instances fed
//! the same blocks in different insertion orders agree on
//! everything.
//!
//! This is the in-process simnet. A Docker simnet was attempted on
//! 2026-11-14: the daemon runs in this VM, but registry pulls are
//! impossible (the sandbox's egress proxy does not carry the
//! daemon's registry traffic, and direct egress is closed), and the
//! VM's ~6 GB RAM would cap real node processes (~2 GB RSS each) at
//! three containers regardless. Scale for consensus purposes —
//! machine count, committee draws, Byzantine share — lives here.

use poe_crypto::pq::DsaKeypair;
use poe_crypto::tickets::TicketChain;
use poe_crypto::xmss::XmssKey;
use poe_dag::Block;
use poe_finality::{Finality, MachineInfo, Vote};
use std::collections::HashMap;

const MACHINES: u64 = 100;
const ROUNDS: u64 = 48;
/// Honest: 0..70. Double-proposers: 70..90. Vote equivocators: 90..100.
const FIRST_DOUBLE_PROPOSER: u64 = 70;
const FIRST_EQUIVOCATOR: u64 = 90;

struct Machine {
    xmss: XmssKey,
    chain: TicketChain,
    dsa: DsaKeypair,
}

fn make_machines(n: u64) -> HashMap<u64, Machine> {
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|id| {
            // Height 7: 128 one-time leaves — an equivocator in every
            // committee signs twice per round (96 ≤ 128).
            let xmss = XmssKey::generate([(id + 1) as u8; 32], 7);
            let chain = TicketChain::new(format!("machine-{id}-secret").as_bytes(), 128);
            let dsa = DsaKeypair::generate(&mut rng);
            (id, Machine { xmss, chain, dsa })
        })
        .collect()
}

fn run_sim(reverse_insertion: bool) -> Finality {
    let mut machines = make_machines(MACHINES);
    let mut fin = Finality::new(3, 16);
    for id in 0..MACHINES {
        let m = &machines[&id];
        fin.register_machine(
            id,
            MachineInfo {
                xmss_root: m.xmss.root(),
                xmss_height: 7,
                chain_commitment: m.chain.commitment(),
                dsa_public_key: m.dsa.public_key_bytes(),
            },
        );
    }
    let genesis = Block::new(0, 0, vec![], b"genesis".to_vec());
    let genesis_id = genesis.id;
    fin.dag.insert(genesis).unwrap();

    let mut pending: Vec<(u64, Vote)> = Vec::new();
    for round in 0..ROUNDS {
        // Deliver the votes that fall due (cast two rounds ago).
        let queued = std::mem::take(&mut pending);
        for (due, v) in queued {
            if due <= round {
                let _ = fin.vote(v);
            } else {
                pending.push((due, v));
            }
        }
        // Reveal phase.
        for id in 0..MACHINES {
            if !fin.is_revoked(id) {
                let link = machines[&id].chain.reveal((round + 1) as usize);
                fin.submit_reveal(id, round, link).unwrap();
            }
        }
        fin.close_round_reveals(round);
        // Proposals. The double-proposers add a second block each round.
        let parents = fin.dag.tips();
        let mut blocks: Vec<Block> = Vec::new();
        for id in 0..MACHINES {
            if fin.is_revoked(id) {
                continue;
            }
            blocks.push(Block::new(id, round, parents.clone(), vec![round as u8, id as u8]));
            if (FIRST_DOUBLE_PROPOSER..FIRST_EQUIVOCATOR).contains(&id) {
                blocks.push(Block::new(id, round, parents.clone(), vec![0xEE, id as u8]));
            }
        }
        if reverse_insertion {
            blocks.reverse();
        }
        for b in blocks {
            let _ = fin.propose(b);
        }
        // Votes are cast now, delivered at round + 2. Honest members
        // vote for the GHOSTDAG-first block of the round; the
        // equivocators vote for two different blocks.
        let committee = fin.committee(round).unwrap().to_vec();
        let order = fin.dag.linearize();
        let of_round = |id: &poe_dag::BlockId| {
            *id != genesis_id && fin.dag.get(id).map(|b| b.round) == Some(round)
        };
        let target = *order.iter().find(|id| of_round(id)).unwrap();
        for id in committee {
            if fin.is_revoked(id) {
                continue;
            }
            if id < FIRST_DOUBLE_PROPOSER {
                let sig = machines.get_mut(&id).unwrap().xmss.sign(&target).unwrap();
                pending.push((round + 2, Vote { machine: id, round, block: target, sig }));
            } else if id >= FIRST_EQUIVOCATOR {
                let other = *order.iter().rev().find(|x| of_round(x) && **x != target).unwrap();
                let s1 = machines.get_mut(&id).unwrap().xmss.sign(&target).unwrap();
                pending.push((round + 2, Vote { machine: id, round, block: target, sig: s1 }));
                let s2 = machines.get_mut(&id).unwrap().xmss.sign(&other).unwrap();
                pending.push((round + 2, Vote { machine: id, round, block: other, sig: s2 }));
            }
            // Double-proposers in the committee abstain (as at the
            // finish line): their misbehavior is the second proposal.
        }
    }
    for (_, v) in pending {
        let _ = fin.vote(v);
    }
    fin
}

#[test]
fn simnet_at_scale_100_machines_30_percent_byzantine() {
    let a = run_sim(false);
    let b = run_sim(true);

    // Agreement: insertion order changes nothing.
    assert_eq!(a.dag.linearize(), b.dag.linearize());
    assert_eq!(a.finalized, b.finalized);

    // Safety + liveness at scale: exactly one final block per round,
    // and every round finalizes despite 30% Byzantine machines and
    // the two-round vote delay.
    assert_eq!(a.finalized.len() as u64, ROUNDS, "every round must finalize");
    for (round, id) in &a.finalized {
        assert_eq!(a.dag.get(id).unwrap().round, *round);
    }

    // Every Byzantine machine produced evidence and is revoked —
    // all twenty double-proposers and all ten equivocators.
    for m in FIRST_DOUBLE_PROPOSER..FIRST_EQUIVOCATOR {
        assert!(
            a.prop_evidence.iter().any(|(mm, ..)| *mm == m),
            "machine {m} double-proposed without evidence"
        );
        assert!(a.is_revoked(m), "machine {m} must be revoked");
    }
    for m in FIRST_EQUIVOCATOR..MACHINES {
        assert!(
            a.vote_evidence.iter().any(|(mm, ..)| *mm == m),
            "machine {m} equivocated without evidence"
        );
        assert!(a.is_revoked(m), "machine {m} must be revoked");
    }

    // Heartbeat crediting: honest machines credited in all three
    // epochs; Byzantine machines are not credited for epoch 0.
    for m in 0..FIRST_DOUBLE_PROPOSER {
        for e in 0..3u64 {
            assert!(a.heartbeat_credited(m, e), "machine {m} must be credited in epoch {e}");
        }
    }
    for m in FIRST_DOUBLE_PROPOSER..MACHINES {
        assert!(!a.heartbeat_credited(m, 0), "Byzantine machine {m} must not be credited");
    }
}
