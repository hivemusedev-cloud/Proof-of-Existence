//! The Step 4 finish line, as a battery: a 10-machine simnet with three
//! Byzantine machines — two double-propose, one equivocates its votes —
//! running 24 rounds with votes delivered two rounds late (a partial-
//! synchrony delay). Expected: every equivocation surfaces as evidence and
//! revocation, exactly one block finalizes per round, finality is reached
//! for all rounds despite the delay, and two instances fed the same
//! blocks in different insertion orders agree on everything.

use poe_crypto::pq::DsaKeypair;
use poe_crypto::tickets::TicketChain;
use poe_crypto::xmss::XmssKey;
use poe_dag::Block;
use poe_finality::{Finality, MachineInfo, Vote};
use std::collections::HashMap;

struct Machine {
    xmss: XmssKey,
    chain: TicketChain,
    dsa: DsaKeypair,
}

fn make_machines(n: u64) -> HashMap<u64, Machine> {
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|id| {
            let xmss = XmssKey::generate([(id + 1) as u8; 32], 5);
            let chain = TicketChain::new(format!("machine-{id}-secret").as_bytes(), 64);
            let dsa = DsaKeypair::generate(&mut rng);
            (id, Machine { xmss, chain, dsa })
        })
        .collect()
}

fn run_sim(reverse_insertion: bool) -> (Finality, HashMap<u64, Machine>) {
    let mut machines = make_machines(10);
    let mut fin = Finality::new(3, 8);
    for id in 0..10u64 {
        let m = &machines[&id];
        fin.register_machine(
            id,
            MachineInfo {
                xmss_root: m.xmss.root(),
                xmss_height: 5,
                chain_commitment: m.chain.commitment(),
                dsa_public_key: m.dsa.public_key_bytes(),
            },
        );
    }
    let genesis = Block::new(0, 0, vec![], b"genesis".to_vec());
    let genesis_id = genesis.id;
    fin.dag.insert(genesis).unwrap();

    let mut pending: Vec<(u64, Vote)> = Vec::new();
    for round in 0..24u64 {
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
        for id in 0..10u64 {
            if !fin.is_revoked(id) {
                let link = machines[&id].chain.reveal((round + 1) as usize);
                fin.submit_reveal(id, round, link).unwrap();
            }
        }
        fin.close_round_reveals(round);
        // Proposals. Machines 8 and 9 double-propose every round they can.
        let parents = fin.dag.tips();
        let mut blocks: Vec<Block> = Vec::new();
        for id in 0..10u64 {
            if fin.is_revoked(id) {
                continue;
            }
            blocks.push(Block::new(id, round, parents.clone(), vec![round as u8, id as u8]));
            if id == 8 || id == 9 {
                blocks.push(Block::new(id, round, parents.clone(), vec![0xEE, id as u8]));
            }
        }
        if reverse_insertion {
            blocks.reverse();
        }
        for b in blocks {
            let _ = fin.propose(b);
        }
        // Votes are cast now, delivered at round + 2. Honest members vote
        // for the GHOSTDAG-first block of the round; machine 7 votes for
        // two different blocks (equivocation).
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
            if id <= 6 {
                let sig = machines.get_mut(&id).unwrap().xmss.sign(&target).unwrap();
                pending.push((round + 2, Vote { machine: id, round, block: target, sig }));
            } else if id == 7 {
                let other = *order.iter().rev().find(|x| of_round(x) && **x != target).unwrap();
                let s1 = machines.get_mut(&7).unwrap().xmss.sign(&target).unwrap();
                pending.push((round + 2, Vote { machine: 7, round, block: target, sig: s1 }));
                let s2 = machines.get_mut(&7).unwrap().xmss.sign(&other).unwrap();
                pending.push((round + 2, Vote { machine: 7, round, block: other, sig: s2 }));
            }
        }
    }
    for (_, v) in pending {
        let _ = fin.vote(v);
    }
    (fin, machines)
}

#[test]
fn byzantine_simnet_evidence_finality_liveness() {
    let (a, _ma) = run_sim(false);
    let (b, _mb) = run_sim(true);

    // Agreement: insertion order changes nothing.
    assert_eq!(a.dag.linearize(), b.dag.linearize());
    assert_eq!(a.finalized, b.finalized);

    // Safety + liveness: exactly one final block per round, and it is a
    // block of that round — despite 30% Byzantine machines and a two-round
    // vote delay. (Conflicting finality is impossible by construction of
    // the map, and this checks the winner is always a real proposal.)
    assert_eq!(a.finalized.len(), 24, "every round must finalize");
    for (round, id) in &a.finalized {
        assert_eq!(a.dag.get(id).unwrap().round, *round);
    }

    // Every Byzantine act produced evidence naming its author, and all
    // three are revoked.
    assert!(a.prop_evidence.iter().any(|(m, ..)| *m == 8), "machine 8 double-proposed");
    assert!(a.prop_evidence.iter().any(|(m, ..)| *m == 9), "machine 9 double-proposed");
    assert!(a.vote_evidence.iter().any(|(m, ..)| *m == 7), "machine 7 equivocated");
    assert!(a.is_revoked(7) && a.is_revoked(8) && a.is_revoked(9));

    // Heartbeat crediting: honest machines cast every owed vote in all
    // three epochs; the Byzantine ones are not credited for epoch 0.
    for m in 0..7u64 {
        for e in 0..3u64 {
            assert!(a.heartbeat_credited(m, e), "machine {m} must be credited in epoch {e}");
        }
    }
    assert!(!a.heartbeat_credited(7, 0));
    assert!(!a.heartbeat_credited(8, 0));
    assert!(!a.heartbeat_credited(9, 0));
}

#[test]
fn heartbeat_signatures_verify() {
    let (fin, mut machines) = run_sim(false);
    let mut rng = rand::thread_rng();
    let msg = fin.heartbeat_message(0);
    let sig = machines.get_mut(&0).unwrap().dsa.sign(&mut rng, &msg);
    assert!(fin.verify_heartbeat(0, 0, &sig).is_ok());
    // The same signature does not verify for another epoch or machine.
    assert!(fin.verify_heartbeat(0, 1, &sig).is_err());
    assert!(fin.verify_heartbeat(1, 0, &sig).is_err());
}
