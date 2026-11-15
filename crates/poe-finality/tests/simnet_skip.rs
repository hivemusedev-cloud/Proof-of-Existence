//! The liveness extension's finish line (2026-11-15): a simnet in the
//! Step-4 harness shape where one round's votes are lost in transit —
//! the stall that used to halt the chain forever. Expected: the next
//! round's committee witnesses the empty round with skip attestations
//! carried on their votes, the stalled round finalizes as a null round
//! (NULL_BLOCK), every later round proceeds, and no round that reached
//! a block quorum is ever overridden by attestations (precedence), with
//! the double actors nameable via `skip_conflicts`.
//!
//! Second battery: attestations attached indiscriminately (every round,
//! finalized or not). Block finality must win everywhere; attestations
//! counted only after their round finalized are inert (never tallied,
//! never recorded), so the conflict query names nobody there.
//!
//! Third battery (hand-driven delivery): one attestation counted while
//! its round is still open, from a machine that also voted for the
//! block that round later finalizes with — `skip_conflicts` must name
//! exactly that machine (or nobody, if the draws kept it off the
//! attested round's committee).

use poe_crypto::pq::DsaKeypair;
use poe_crypto::tickets::TicketChain;
use poe_crypto::xmss::XmssKey;
use poe_dag::Block;
use poe_finality::{skip_message, Finality, MachineInfo, Vote, NULL_BLOCK};
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
            let xmss = XmssKey::generate([(id + 1) as u8; 32], 6);
            let chain = TicketChain::new(format!("machine-{id}-secret").as_bytes(), 64);
            let dsa = DsaKeypair::generate(&mut rng);
            (id, Machine { xmss, chain, dsa })
        })
        .collect()
}

/// Run 16 honest rounds. If `stall_round` is Some(r), all but one of
/// round r's votes are lost. If `attest_always`, every vote carries a
/// skip attestation for the previous round; otherwise a vote carries
/// one only when the previous round is unfinalized in the shared
/// record at cast time (the node's own rule).
fn run_sim(stall_round: Option<u64>, attest_always: bool) -> Finality {
    let mut machines = make_machines(10);
    let mut fin = Finality::new(3, 8);
    for id in 0..10u64 {
        let m = &machines[&id];
        fin.register_machine(
            id,
            MachineInfo {
                xmss_root: m.xmss.root(),
                xmss_height: 6,
                chain_commitment: m.chain.commitment(),
                dsa_public_key: m.dsa.public_key_bytes(),
            },
        );
    }
    let genesis = Block::new(0, 0, vec![], b"genesis".to_vec());
    let genesis_id = genesis.id;
    fin.dag.insert(genesis).unwrap();

    let mut pending: Vec<(u64, Vote)> = Vec::new();
    for round in 0..16u64 {
        let queued = std::mem::take(&mut pending);
        for (due, v) in queued {
            if due <= round {
                let _ = fin.vote(v);
            } else {
                pending.push((due, v));
            }
        }
        for id in 0..10u64 {
            if !fin.is_revoked(id) {
                let link = machines[&id].chain.reveal((round + 1) as usize);
                fin.submit_reveal(id, round, link).unwrap();
            }
        }
        fin.close_round_reveals(round);
        let parents = fin.dag.tips();
        for id in 0..10u64 {
            if fin.is_revoked(id) {
                continue;
            }
            let b = Block::new(id, round, parents.clone(), vec![round as u8, id as u8]);
            let _ = fin.propose(b);
        }
        // Votes for this round, delivered two rounds later (the Step-4
        // partial-synchrony delay). The stall: round `stall_round`'s
        // votes are lost except the first caster's.
        let committee = fin.committee(round).unwrap().to_vec();
        let order = fin.dag.linearize();
        let of_round = |id: &poe_dag::BlockId| {
            *id != genesis_id && fin.dag.get(id).map(|b| b.round) == Some(round)
        };
        let target = *order.iter().find(|id| of_round(id)).unwrap();
        let mut casters = 0u64;
        for id in committee {
            if fin.is_revoked(id) {
                continue;
            }
            if stall_round == Some(round) {
                casters += 1;
                if casters > 1 {
                    continue; // this vote is lost in transit
                }
            }
            let sig = machines.get_mut(&id).unwrap().xmss.sign(&target).unwrap();
            // The node's attestation rule: witness the previous round
            // empty if it has not finalized in the record.
            let attest = round >= 1 && (attest_always || !fin.finalized.contains_key(&(round - 1)));
            let skip = if attest {
                let msg = skip_message(round - 1);
                Some(machines.get_mut(&id).unwrap().xmss.sign(&msg).unwrap())
            } else {
                None
            };
            pending.push((round + 2, Vote { machine: id, round, block: target, sig, skip }));
        }
    }
    for (_, v) in pending {
        let _ = fin.vote(v);
    }
    fin
}

#[test]
fn lost_votes_stall_is_witnessed_and_the_chain_advances() {
    let fin = run_sim(Some(5), false);
    assert_eq!(fin.finalized.len(), 16, "every round must finalize, stalled or not");
    assert_eq!(fin.finalized[&5], NULL_BLOCK, "the stalled round closes as a null round");
    for (round, id) in &fin.finalized {
        if *round != 5 {
            assert_eq!(fin.dag.get(id).unwrap().round, *round, "round {round} finalizes with a real block");
        }
    }
    // The attestation tally for round 5 crossed two thirds of round
    // 6's committee, and nobody double-acted: every attestor's own
    // round-5 vote was among the lost ones, never cast here.
    let (n, size) = fin.skip_tally(5);
    assert!(size > 0 && n * 3 > 2 * size, "skip quorum must have formed: {n}/{size}");
    assert!(fin.skip_conflicts().is_empty(), "no double actors on an honest record");
}

#[test]
fn block_finality_takes_precedence_over_attestations() {
    let fin = run_sim(None, true);
    assert_eq!(fin.finalized.len(), 16, "every round must finalize");
    for (round, id) in &fin.finalized {
        assert_ne!(*id, NULL_BLOCK, "round {round} reached a block quorum; null must not override");
        assert_eq!(fin.dag.get(id).unwrap().round, *round);
    }
    // Inertness: in this harness a round's votes are delivered a full
    // round before the attestations about it are counted, so every
    // attestation here is counted only after its round already
    // finalized — late attestations are inert, exactly like late
    // votes: no recorded tally may cross the threshold, and the
    // conflict query (which reads only live attestations) names
    // nobody. The detector's positive case is exercised by
    // `skip_conflicts_name_live_double_actors` below.
    for round in 0..16u64 {
        let (count, size) = fin.skip_tally(round);
        assert!(
            count * 3 <= 2 * size,
            "round {round}: late attestations must stay inert (tally {count}/{size})"
        );
    }
    assert!(fin.skip_conflicts().is_empty(), "no live attestation, no conflict");
}

#[test]
fn skip_conflicts_name_live_double_actors() {
    let mut machines = make_machines(10);
    let mut fin = Finality::new(3, 8);
    for id in 0..10u64 {
        let m = &machines[&id];
        fin.register_machine(
            id,
            MachineInfo {
                xmss_root: m.xmss.root(),
                xmss_height: 6,
                chain_commitment: m.chain.commitment(),
                dsa_public_key: m.dsa.public_key_bytes(),
            },
        );
    }
    let genesis = Block::new(0, 0, vec![], b"genesis".to_vec());
    let genesis_id = genesis.id;
    fin.dag.insert(genesis).unwrap();

    // One round of the harness flow (reveals, close, proposals, committee
    // votes for the round's first block in the linearization), returning
    // the votes WITHOUT delivering them — delivery order is the test's
    // whole point.
    fn play_round(
        fin: &mut Finality,
        machines: &mut HashMap<u64, Machine>,
        genesis_id: poe_dag::BlockId,
        round: u64,
    ) -> (Vec<u64>, poe_dag::BlockId, Vec<Vote>) {
        for id in 0..10u64 {
            if !fin.is_revoked(id) {
                let link = machines[&id].chain.reveal((round + 1) as usize);
                fin.submit_reveal(id, round, link).unwrap();
            }
        }
        fin.close_round_reveals(round);
        let parents = fin.dag.tips();
        for id in 0..10u64 {
            if fin.is_revoked(id) {
                continue;
            }
            let b = Block::new(id, round, parents.clone(), vec![round as u8, id as u8]);
            let _ = fin.propose(b);
        }
        let committee = fin.committee(round).unwrap().to_vec();
        let order = fin.dag.linearize();
        let target = *order
            .iter()
            .find(|id| **id != genesis_id && fin.dag.get(id).map(|b| b.round) == Some(round))
            .unwrap();
        let mut votes = Vec::new();
        for id in &committee {
            if fin.is_revoked(*id) {
                continue;
            }
            let sig = machines.get_mut(id).unwrap().xmss.sign(&target).unwrap();
            votes.push(Vote { machine: *id, round, block: target, sig, skip: None });
        }
        (committee, target, votes)
    }

    // Round 0: delivered at once, finalizes with its block.
    let (_, target0, votes0) = play_round(&mut fin, &mut machines, genesis_id, 0);
    for v in votes0 {
        let _ = fin.vote(v);
    }
    assert_eq!(fin.finalized.get(&0), Some(&target0));

    // Round 1: votes cast but HELD — the round stays open.
    let (committee1, target1, votes1) = play_round(&mut fin, &mut machines, genesis_id, 1);

    // Round 2: exactly one committee member attests round 1 empty,
    // chosen from the overlap with round 1's committee when the draws
    // allow (the double-actor case); its vote is delivered while
    // round 1 is still open, so the attestation is LIVE — but a single
    // attestation is far below the >2/3 tally, so round 1 must stay
    // open.
    let (committee2, _target2, mut votes2) = play_round(&mut fin, &mut machines, genesis_id, 2);
    let attester = committee2
        .iter()
        .copied()
        .find(|id| committee1.contains(id))
        .unwrap_or(committee2[0]);
    let msg = skip_message(1);
    let skip_sig = machines.get_mut(&attester).unwrap().xmss.sign(&msg).unwrap();
    for v in &mut votes2 {
        if v.machine == attester {
            v.skip = Some(skip_sig.clone());
        }
    }
    for v in votes2 {
        let _ = fin.vote(v);
    }
    assert!(!fin.finalized.contains_key(&1), "one attestation must not close round 1");
    let (n, size) = fin.skip_tally(1);
    assert_eq!(n, 1, "the live attestation is recorded");
    assert!(size >= 2, "committee of {size}: a single attestation is below quorum by construction of this test");

    // Round 1's held votes now arrive: the round finalizes with its
    // block (precedence — the live attestation never had a quorum, and
    // even a quorum could not have overridden a reached block finality).
    for v in votes1 {
        let _ = fin.vote(v);
    }
    assert_eq!(fin.finalized.get(&1), Some(&target1));

    // The detector names the attester exactly when it also voted for
    // round 1's winning block — and names nobody else, for any round.
    let conflicts = fin.skip_conflicts();
    if committee1.contains(&attester) {
        assert_eq!(
            conflicts,
            vec![(attester, 1, target1)],
            "the live double actor, and only it, is named"
        );
    } else {
        assert!(conflicts.is_empty(), "the attester never voted in round 1: nobody to name");
    }
}
