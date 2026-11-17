//! Finality certificates (addition #1, 2026-11-17): a simnet epoch is
//! driven to finality, its closing round's certificate is emitted and
//! verified from evidence alone, and a battery of tampered
//! certificates is refused for the right reason.

use poe_crypto::pq::DsaKeypair;
use poe_crypto::tickets::TicketChain;
use poe_crypto::xmss::XmssKey;
use poe_dag::Block;
use poe_finality::cert::{
    announcement_statement, announcements_hash, decode_certificate, device_id_of,
    encode_certificate, verify_certificate, CertError,
};
use poe_finality::{Announcement, Finality, MachineInfo, Vote, NULL_BLOCK};
use std::collections::{BTreeMap, HashMap};

struct Machine {
    xmss: XmssKey,
    chain: TicketChain,
    dsa: DsaKeypair,
}

struct World {
    root: DsaKeypair,
    root_pk: Vec<u8>,
    machines: HashMap<u64, Machine>,
    announcements: BTreeMap<u64, Announcement>,
    /// An announced machine that never registers, reveals, or votes:
    /// the outsider whose forged vote must read NotCommittee.
    outsider: u64,
}

fn make_world() -> World {
    let mut rng = rand::thread_rng();
    let root = DsaKeypair::generate(&mut rng);
    let root_pk = root.public_key_bytes();
    let mut machines = HashMap::new();
    let mut announcements = BTreeMap::new();
    let mut ids = Vec::new();
    for i in 0..7u64 {
        let dsa = DsaKeypair::generate(&mut rng);
        let pk = dsa.public_key_bytes();
        let id = device_id_of(&pk);
        assert!(!ids.contains(&id), "device ids must be distinct");
        ids.push(id);
        let xmss = XmssKey::generate([(i + 1) as u8; 32], 6);
        let chain = TicketChain::new(format!("cert-machine-{i}-secret").as_bytes(), 64);
        let mut a = Announcement {
            device_pk: pk,
            root_id: 1,
            serial: 100 + i,
            expiry_epoch: 10_000,
            root_signature: Vec::new(),
            xmss_root: xmss.root(),
            xmss_height: 6,
            chain_commitment: chain.commitment(),
            sync_hint: 0,
        };
        a.root_signature = root.sign(&mut rng, &announcement_statement(&a));
        announcements.insert(id, a);
        machines.insert(id, Machine { xmss, chain, dsa });
    }
    let outsider = ids[6];
    World { root, root_pk, machines, announcements, outsider }
}

/// Drive two epochs (rounds 0..8, four rounds per epoch) to full
/// block finality with immediate vote delivery.
fn run_two_epochs(w: &mut World) -> Finality {
    let mut fin = Finality::new(3, 4);
    let active: Vec<u64> = w
        .announcements
        .keys()
        .copied()
        .filter(|m| *m != w.outsider)
        .collect();
    for id in &active {
        let m = &w.machines[id];
        fin.register_machine(
            *id,
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
    for round in 0..8u64 {
        for id in &active {
            let link = w.machines[id].chain.reveal((round + 1) as usize);
            fin.submit_reveal(*id, round, link).unwrap();
        }
        fin.close_round_reveals(round);
        let parents = fin.dag.tips();
        for id in &active {
            let payload = format!("cert-{id}-{round}").into_bytes();
            let _ = fin.propose(Block::new(*id, round, parents.clone(), payload));
        }
        let order = fin.dag.linearize();
        let target = *order
            .iter()
            .find(|b| **b != genesis_id && fin.dag.get(b).map(|x| x.round) == Some(round))
            .unwrap();
        let committee = fin.committee(round).unwrap().to_vec();
        for id in committee {
            let sig = w.machines.get_mut(&id).unwrap().xmss.sign(&target).unwrap();
            fin.vote(Vote { machine: id, round, block: target, sig, skip: None }).unwrap();
        }
        assert_eq!(fin.finalized.get(&round), Some(&target), "round {round} finalizes");
    }
    fin
}

#[test]
fn certificates_verify_from_evidence_and_tampering_is_refused() {
    let mut w = make_world();
    let fin = run_two_epochs(&mut w);
    let genesis_root = [1u8; 64];
    let root0 = [2u8; 64];
    let root1 = [3u8; 64];

    // Emission: both epochs certify; an unfinalized epoch does not.
    let companion = [5u8; 64];
    let cert0 = fin
        .certificate(0, genesis_root, root0, companion, 300_000, &w.announcements)
        .expect("epoch 0 certifies");
    let cert1 = fin
        .certificate(1, root0, root1, companion, 600_000, &w.announcements)
        .expect("epoch 1 certifies");
    assert!(fin.certificate(5, root1, root1, companion, 0, &w.announcements).is_none());
    assert_eq!(cert0.companion_root, companion, "the companion root is named in the certificate");
    assert_eq!(cert0.close_round, 3);
    assert_eq!(cert1.close_round, 7);
    assert_eq!(cert0.close_block, fin.finalized[&3]);
    assert_eq!(cert0.votes.len(), 6, "the whole committee voted");

    // Verification from evidence alone, chained.
    assert_eq!(verify_certificate(&cert0, &w.root_pk, &genesis_root), Ok(()));
    assert_eq!(verify_certificate(&cert1, &w.root_pk, &root0), Ok(()));
    assert_eq!(
        verify_certificate(&cert1, &w.root_pk, &genesis_root),
        Err(CertError::BadChainLink),
        "a certificate chained to the wrong predecessor is refused"
    );

    // The wire format round-trips, and the decoded copy verifies.
    let bytes = encode_certificate(&cert0);
    let back = decode_certificate(&bytes).expect("decodes");
    assert_eq!(encode_certificate(&back), bytes, "canonical round trip");
    assert_eq!(verify_certificate(&back, &w.root_pk, &genesis_root), Ok(()));
    assert!(decode_certificate(&bytes[..bytes.len() - 1]).is_none(), "truncation refused");
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(decode_certificate(&longer).is_none(), "trailing bytes refused");

    // Tamper battery.
    let mut c = cert0.clone();
    c.close_block = NULL_BLOCK;
    assert_eq!(verify_certificate(&c, &w.root_pk, &genesis_root), Err(CertError::NullClose));

    let mut c = cert0.clone();
    c.announcements_hash = [0u8; 64];
    assert_eq!(
        verify_certificate(&c, &w.root_pk, &genesis_root),
        Err(CertError::BadAnnouncementHash)
    );

    let mut c = cert0.clone();
    c.announcements[0].1.root_signature[0] ^= 1;
    assert_eq!(
        verify_certificate(&c, &w.root_pk, &genesis_root),
        Err(CertError::BadAnnouncementSignature)
    );

    let mut c = cert0.clone();
    let pk = c.announcements[0].1.device_pk.clone();
    c.announcements[0].1.device_pk = c.announcements[1].1.device_pk.clone();
    c.announcements[1].1.device_pk = pk;
    assert_eq!(
        verify_certificate(&c, &w.root_pk, &genesis_root),
        Err(CertError::MachineIdMismatch),
        "an announcement bound to another machine's id is refused"
    );

    let mut c = cert0.clone();
    let mut rng = rand::thread_rng();
    c.announcements[0].1.expiry_epoch = 0;
    let stmt = announcement_statement(&c.announcements[0].1);
    c.announcements[0].1.root_signature = w.root.sign(&mut rng, &stmt);
    c.announcements_hash = announcements_hash(&c.announcements);
    assert_eq!(
        verify_certificate(&c, &w.root_pk, &genesis_root),
        Err(CertError::AnnouncementExpired),
        "even correctly re-signed, an expired announcement is refused"
    );

    let mut c = cert0.clone();
    let last = c.reveals.len() - 1;
    c.reveals[last].0 = u64::MAX;
    assert_eq!(
        verify_certificate(&c, &w.root_pk, &genesis_root),
        Err(CertError::UnknownMachine),
        "a reveal from an unannounced machine is refused"
    );

    let mut c = cert0.clone();
    c.reveals[0].1[0] ^= 1;
    assert_eq!(verify_certificate(&c, &w.root_pk, &genesis_root), Err(CertError::BadReveal));

    let mut c = cert0.clone();
    c.votes.drain(..2);
    assert_eq!(
        verify_certificate(&c, &w.root_pk, &genesis_root),
        Err(CertError::NoQuorum),
        "four of six is not more than two thirds"
    );

    let mut c = cert0.clone();
    c.votes[0].block = [42u8; 64];
    assert_eq!(
        verify_certificate(&c, &w.root_pk, &genesis_root),
        Err(CertError::VoteBlockMismatch)
    );

    let mut c = cert0.clone();
    c.votes[0].sig.wots[0][0] ^= 1;
    assert_eq!(
        verify_certificate(&c, &w.root_pk, &genesis_root),
        Err(CertError::BadVoteSignature)
    );

    // The outsider is announced and its signature is genuine — but it
    // never revealed, so it is not in the committee.
    let mut c = cert0.clone();
    let sig = w
        .machines
        .get_mut(&w.outsider)
        .unwrap()
        .xmss
        .sign(&c.close_block)
        .unwrap();
    c.votes.push(Vote { machine: w.outsider, round: c.close_round, block: c.close_block, sig, skip: None });
    assert_eq!(
        verify_certificate(&c, &w.root_pk, &genesis_root),
        Err(CertError::NotCommittee)
    );

    // The mirror of poe_identity::device_id (cert::device_id_of) is
    // the same function the node registers machines by.
    for (m, a) in &w.announcements {
        assert_eq!(*m, poe_identity::device_id(&a.device_pk));
    }
}
