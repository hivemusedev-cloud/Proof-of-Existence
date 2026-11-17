//! The light core (Phase 2, 2026-11-17): what the light-duty
//! design note (POE_LIGHT_DUTY_DESIGN.md §11, build order item 4)
//! puts in the phone beyond its identity — the wallet's Existence
//! Containers and finality-certificate verification, over the same
//! Rust crates the node uses (poe-wallet, poe-finality), never a
//! reimplementation.
//!
//! Containers: the phone holds a coin's 1 KiB container, shows it
//! offline at a terminal's challenge, and records every show in
//! the container's own log (a second show at the same challenge is
//! refused by the log — that refusal is the honest wallet's side
//! of the double-show extraction rule). The container's line
//! secret is never exposed through this surface: summaries carry
//! the coin's public fields only, and a show returns exactly the
//! (coin, challenge, response) triple a terminal needs.
//!
//! Certificates: the phone verifies an epoch's finality
//! certificate from its evidence alone — the same
//! `poe_finality::cert::verify_certificate` the node's own tests
//! exercise — against a root key it pins and the state root of
//! the last certificate it accepted. `verify_testnet_certificate`
//! pins the poe-testnet-1 root (public by design; the key below
//! is the root_pk of crates/poe-node/testnet-1.spec, copied
//! verbatim). The chain-link rule is the caller's: for the first
//! certificate a light client accepts, the expected predecessor
//! root comes from its sync source (a bundle or a serving node),
//! exactly as the design note's §3 describes; afterwards each
//! certificate chains to the previous one's state root.

use poe_finality::cert::{decode_certificate, verify_certificate};
use poe_wallet::{show as wallet_show, Container};
use std::sync::{Arc, Mutex};

/// Why a light-core call failed.
#[derive(Debug, uniffi::Error)]
pub enum LightCoreError {
    /// The container bytes are not a valid Existence Container.
    BadContainer { reason: String },
    /// The certificate bytes do not decode.
    BadCertificate { reason: String },
    /// The certificate decoded but its evidence does not verify.
    VerificationFailed { reason: String },
    /// A detection input (secret, tag stream, book state) is malformed.
    BadDetection { reason: String },
}

impl std::fmt::Display for LightCoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LightCoreError::BadContainer { reason } => write!(f, "bad container: {reason}"),
            LightCoreError::BadCertificate { reason } => {
                write!(f, "bad certificate: {reason}")
            }
            LightCoreError::VerificationFailed { reason } => {
                write!(f, "certificate does not verify: {reason}")
            }
            LightCoreError::BadDetection { reason } => {
                write!(f, "bad detection input: {reason}")
            }
        }
    }
}

impl std::error::Error for LightCoreError {}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

// -- containers ---------------------------------------------------------------

/// A container's public summary. Deliberately carries no line
/// secret and no blind: those never leave the container object.
#[derive(Debug, uniffi::Record)]
pub struct ContainerInfo {
    pub coin: u64,
    pub nf: u64,
    pub asset: u64,
    pub value: u64,
    pub born: u64,
    pub owner: u64,
    /// How many shows this container has recorded.
    pub shows_recorded: u32,
}

/// One offline show, as handed to a terminal: the triple a
/// merchant's policy checks, and two of which (at different
/// challenges) would unmask the coin's line secret — the
/// double-spend evidence.
#[derive(Debug, uniffi::Record)]
pub struct ShowInfo {
    pub coin: u64,
    pub challenge: u64,
    pub response: u64,
    pub counterparty: u64,
}

/// A held Existence Container (one coin). Created from the
/// canonical 1 KiB serialization; `to_bytes` returns it (with the
/// show log as it now stands) for the app to store under its
/// platform custody.
#[derive(uniffi::Object)]
pub struct WalletContainer {
    inner: Mutex<Container>,
}

#[uniffi::export]
impl WalletContainer {
    /// Import a container from its 1 KiB serialization (the
    /// `.poec` form the node's control surface exports). The
    /// checksum inside the format is verified by poe-wallet; a
    /// damaged or forged container is refused.
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Arc<Self>, LightCoreError> {
        Container::from_bytes(&bytes)
            .map(|c| Arc::new(WalletContainer { inner: Mutex::new(c) }))
            .map_err(|reason| LightCoreError::BadContainer { reason })
    }

    /// The canonical 1 KiB serialization, for storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.lock().expect("container lock").to_bytes().to_vec()
    }

    /// The container's public summary (no secret material).
    pub fn info(&self) -> ContainerInfo {
        let c = self.inner.lock().expect("container lock");
        ContainerInfo {
            coin: c.coin,
            nf: c.nf,
            asset: c.asset,
            value: c.value,
            born: c.born,
            owner: c.owner,
            shows_recorded: c.shows.len() as u32,
        }
    }

    /// Show the coin at `challenge` for `counterparty`, recording
    /// the show in the container's log. Refused if this coin was
    /// already shown at that challenge (the log's rule) or the log
    /// is full. The caller must persist `to_bytes()` afterwards —
    /// an unrecorded show is exactly what the log exists to
    /// prevent.
    pub fn show(&self, challenge: u64, counterparty: u64) -> Result<ShowInfo, LightCoreError> {
        let mut c = self.inner.lock().expect("container lock");
        let s = wallet_show(&c.line, c.coin, challenge);
        c.record_show(&s, counterparty)
            .map_err(|reason| LightCoreError::BadContainer { reason })?;
        Ok(ShowInfo { coin: s.coin, challenge: s.challenge, response: s.response, counterparty })
    }

    /// The shows this container has recorded, in order.
    pub fn recorded_shows(&self) -> Vec<ShowInfo> {
        let c = self.inner.lock().expect("container lock");
        c.shows
            .iter()
            .map(|r| ShowInfo {
                coin: c.coin,
                challenge: r.challenge,
                response: r.response,
                counterparty: r.counterparty,
            })
            .collect()
    }
}

// -- certificates -------------------------------------------------------------

/// A certificate's summary — what the app shows after decoding or
/// verifying. Roots are lowercase hex (128 chars); `minted` is a
/// decimal string because it does not fit in a u64.
#[derive(Debug, uniffi::Record)]
pub struct CertSummary {
    pub epoch: u64,
    pub close_round: u64,
    pub minted: String,
    pub prev_state_root: String,
    pub state_root: String,
    pub companion_root: String,
    pub announcements: u32,
    pub reveals: u32,
    pub votes: u32,
}

fn summarize(c: &poe_finality::cert::Certificate) -> CertSummary {
    CertSummary {
        epoch: c.epoch,
        close_round: c.close_round,
        minted: c.minted.to_string(),
        prev_state_root: hex_encode(&c.prev_state_root),
        state_root: hex_encode(&c.state_root),
        companion_root: hex_encode(&c.companion_root),
        announcements: c.announcements.len() as u32,
        reveals: c.reveals.len() as u32,
        votes: c.votes.len() as u32,
    }
}

fn root_from_bytes(b: &[u8]) -> Result<[u8; 64], LightCoreError> {
    b.try_into().map_err(|_| LightCoreError::BadCertificate {
        reason: "an expected state root is exactly 64 bytes".into(),
    })
}

/// Decode a certificate's summary WITHOUT verifying it. For
/// display of an untrusted file's claims only — the app must not
/// present these as verified; `verify_certificate_bytes` is the
/// verification entry point.
#[uniffi::export]
pub fn certificate_summary(bytes: Vec<u8>) -> Result<CertSummary, LightCoreError> {
    decode_certificate(&bytes).map(|c| summarize(&c)).ok_or_else(|| {
        LightCoreError::BadCertificate { reason: "not a POECERT1 certificate".into() }
    })
}

/// Verify a certificate from its evidence alone, against a
/// pinned attestation root key and the state root of the last
/// certificate accepted. On success returns the summary; the
/// caller chains the next certificate to `summary.state_root`.
#[uniffi::export]
pub fn verify_certificate_bytes(
    bytes: Vec<u8>,
    root_public_key: Vec<u8>,
    expected_prev_root: Vec<u8>,
) -> Result<CertSummary, LightCoreError> {
    let cert = decode_certificate(&bytes).ok_or_else(|| LightCoreError::BadCertificate {
        reason: "not a POECERT1 certificate".into(),
    })?;
    let expected = root_from_bytes(&expected_prev_root)?;
    verify_certificate(&cert, &root_public_key, &expected).map_err(|e| {
        LightCoreError::VerificationFailed { reason: format!("{e:?}") }
    })?;
    Ok(summarize(&cert))
}

/// The poe-testnet-1 attestation root's public key (public by
/// design; copied verbatim from crates/poe-node/testnet-1.spec).
#[uniffi::export]
pub fn testnet_root_public_key() -> Vec<u8> {
    hex_decode(include_str!("testnet_root_pk.hex")).expect("embedded testnet root pk is valid hex")
}

/// Verify a certificate against the pinned testnet root.
#[uniffi::export]
pub fn verify_testnet_certificate(
    bytes: Vec<u8>,
    expected_prev_root: Vec<u8>,
) -> Result<CertSummary, LightCoreError> {
    verify_certificate_bytes(bytes, testnet_root_public_key(), expected_prev_root)
}

// -- detection ----------------------------------------------------------------

/// One arrival found by a scan.
#[derive(Debug, uniffi::Record)]
pub struct DetectionHit {
    pub contact: String,
    pub counter: u64,
    pub epoch: u64,
}

/// The phone's detection book (design note §5): the pairwise
/// secrets it holds with its contacts and each contact's next
/// expected counter, over poe-wallet's `Scanner`. Secrets are
/// add-only — no method returns one — and the whole book
/// exports as opaque state bytes for the platform's custody
/// store (on Android, a Keystore-wrapped blob).
#[derive(uniffi::Object)]
pub struct DetectionBook {
    inner: Mutex<poe_wallet::Scanner>,
}

#[uniffi::export]
impl DetectionBook {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(DetectionBook { inner: Mutex::new(poe_wallet::Scanner::new()) })
    }

    /// Restore a book from custody state bytes.
    #[uniffi::constructor]
    pub fn from_state(bytes: Vec<u8>) -> Result<Arc<Self>, LightCoreError> {
        let sc = poe_wallet::Scanner::import_state(&bytes).ok_or_else(|| {
            LightCoreError::BadDetection { reason: "book state does not decode".into() }
        })?;
        Ok(Arc::new(DetectionBook { inner: Mutex::new(sc) }))
    }

    /// The book as custody state bytes (secret material —
    /// store only inside the encrypted custody store).
    pub fn export_state(&self) -> Vec<u8> {
        self.inner.lock().unwrap().export_state()
    }

    /// Add (or replace) a contact's 32-byte pairwise secret.
    pub fn add_contact(&self, name: String, secret: Vec<u8>) -> Result<(), LightCoreError> {
        let secret: [u8; 32] = secret.try_into().map_err(|_| LightCoreError::BadDetection {
            reason: "a pairwise secret is exactly 32 bytes".into(),
        })?;
        self.inner.lock().unwrap().add_contact(&name, secret);
        Ok(())
    }

    pub fn remove_contact(&self, name: String) -> bool {
        self.inner.lock().unwrap().remove_contact(&name)
    }

    pub fn contacts(&self) -> Vec<String> {
        self.inner.lock().unwrap().contacts()
    }

    pub fn next_counter(&self, name: String) -> Option<u64> {
        self.inner.lock().unwrap().next_counter(&name)
    }

    /// Scan a candidate tag stream — concatenated 56-byte
    /// tags as relayed — for arrivals in the epoch window
    /// `from_epoch..=to_epoch`. Returns the matches and
    /// advances each matched contact's next counter, so a
    /// settled tag never matches again.
    pub fn scan(
        &self,
        tag_stream: Vec<u8>,
        from_epoch: u64,
        to_epoch: u64,
        lookahead: u64,
    ) -> Result<Vec<DetectionHit>, LightCoreError> {
        if tag_stream.len() % poe_wallet::detect::TAG_BYTES != 0 {
            return Err(LightCoreError::BadDetection {
                reason: format!(
                    "tag stream length {} is not a multiple of {}",
                    tag_stream.len(),
                    poe_wallet::detect::TAG_BYTES
                ),
            });
        }
        let candidates: Vec<poe_wallet::DetectionTag> = tag_stream
            .chunks_exact(poe_wallet::detect::TAG_BYTES)
            .map(|c| poe_wallet::DetectionTag::from_bytes(c).expect("chunk is tag-sized"))
            .collect();
        let epochs: Vec<u64> = (from_epoch..=to_epoch).collect();
        let found = self.inner.lock().unwrap().scan(&candidates, &epochs, lookahead);
        Ok(found
            .into_iter()
            .map(|m| DetectionHit { contact: m.contact, counter: m.counter, epoch: m.epoch })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use poe_crypto::pq::DsaKeypair;
    use poe_crypto::tickets::TicketChain;
    use poe_crypto::xmss::XmssKey;
    use poe_dag::Block;
    use poe_finality::cert::{announcement_statement, encode_certificate};
    use poe_finality::{Announcement, Finality, MachineInfo, Vote};
    use poe_wallet::LineKey;
    use std::collections::{BTreeMap, HashMap};

    #[test]
    fn container_shows_record_and_two_shows_extract() {
        let fixture = Container {
            coin: 42,
            nf: 4242,
            asset: 0,
            value: 500,
            born: 3,
            owner: 7,
            line: LineKey { secret: 111, blind: 222 },
            shows: Vec::new(),
        };
        let bytes = fixture.to_bytes().to_vec();
        let c = WalletContainer::from_bytes(bytes).expect("import");
        let info = c.info();
        assert_eq!(info.coin, 42);
        assert_eq!(info.value, 500);
        assert_eq!(info.shows_recorded, 0);

        // Two shows at different challenges extract the line
        // secret — the double-show rule, through this surface.
        let s1 = c.show(1000, 9).expect("first show");
        let s2 = c.show(2000, 9).expect("second show");
        let a = poe_wallet::Show { coin: s1.coin, challenge: s1.challenge, response: s1.response };
        let b = poe_wallet::Show { coin: s2.coin, challenge: s2.challenge, response: s2.response };
        assert_eq!(poe_wallet::extract_secret(&a, &b), Some(111));
        assert_eq!(c.info().shows_recorded, 2);
        assert_eq!(c.recorded_shows().len(), 2);

        // The log refuses a repeat challenge, and the persisted
        // bytes carry the log across a re-import.
        assert!(c.show(1000, 9).is_err());
        let restored = WalletContainer::from_bytes(c.to_bytes()).expect("re-import");
        assert_eq!(restored.info().shows_recorded, 2);

        // Damaged bytes are refused by the format's checksum.
        let mut bad = c.to_bytes();
        bad[100] ^= 1;
        assert!(WalletContainer::from_bytes(bad).is_err());
    }

    /// A one-epoch finality world, driven like poe-finality's own
    /// certificate battery, whose epoch-0 certificate must verify
    /// through this crate's byte surface — and fail through it
    /// when the chain link or a vote is wrong.
    #[test]
    fn certificate_verifies_through_the_byte_surface() {
        let mut rng = rand::thread_rng();
        let root = DsaKeypair::generate(&mut rng);
        let root_pk = root.public_key_bytes();
        let mut machines: HashMap<u64, (XmssKey, TicketChain, DsaKeypair)> = HashMap::new();
        let mut announcements: BTreeMap<u64, Announcement> = BTreeMap::new();
        for i in 0..7u64 {
            let dsa = DsaKeypair::generate(&mut rng);
            let pk = dsa.public_key_bytes();
            let id = poe_finality::cert::device_id_of(&pk);
            let xmss = XmssKey::generate([(i + 1) as u8; 32], 6);
            let chain = TicketChain::new(format!("mobile-cert-{i}").as_bytes(), 64);
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
            machines.insert(id, (xmss, chain, dsa));
        }
        let active: Vec<u64> = announcements.keys().copied().take(6).collect();
        let mut fin = Finality::new(3, 4);
        for id in &active {
            let (xmss, chain, dsa) = &machines[id];
            fin.register_machine(
                *id,
                MachineInfo {
                    xmss_root: xmss.root(),
                    xmss_height: 6,
                    chain_commitment: chain.commitment(),
                    dsa_public_key: dsa.public_key_bytes(),
                },
            );
        }
        let genesis = Block::new(0, 0, vec![], b"genesis".to_vec());
        let genesis_id = genesis.id;
        fin.dag.insert(genesis).unwrap();
        for round in 0..4u64 {
            for id in &active {
                let link = machines[id].1.reveal((round + 1) as usize);
                fin.submit_reveal(*id, round, link).unwrap();
            }
            fin.close_round_reveals(round);
            let parents = fin.dag.tips();
            for id in &active {
                let _ = fin.propose(Block::new(
                    *id,
                    round,
                    parents.clone(),
                    format!("m-{id}-{round}").into_bytes(),
                ));
            }
            let order = fin.dag.linearize();
            let target = *order
                .iter()
                .find(|b| **b != genesis_id && fin.dag.get(b).map(|x| x.round) == Some(round))
                .unwrap();
            let committee = fin.committee(round).unwrap().to_vec();
            for id in committee {
                let sig = machines.get_mut(&id).unwrap().0.sign(&target).unwrap();
                fin.vote(Vote { machine: id, round, block: target, sig, skip: None }).unwrap();
            }
            assert_eq!(fin.finalized.get(&round), Some(&target));
        }

        let prev = [1u8; 64];
        let cert = fin
            .certificate(0, prev, [2u8; 64], [5u8; 64], 300_000, &announcements)
            .expect("epoch 0 certifies");
        let bytes = encode_certificate(&cert);

        // Summary decodes; verification passes with the right
        // predecessor and fails with the wrong one, naming the
        // chain link.
        let summary = certificate_summary(bytes.clone()).expect("summary");
        assert_eq!(summary.epoch, 0);
        assert_eq!(summary.close_round, 3);
        assert_eq!(summary.minted, "300000");
        assert_eq!(summary.votes, 6);
        let ok = verify_certificate_bytes(bytes.clone(), root_pk.clone(), prev.to_vec())
            .expect("verifies");
        assert_eq!(ok.state_root, summary.state_root);
        match verify_certificate_bytes(bytes.clone(), root_pk, vec![9u8; 64]) {
            Err(LightCoreError::VerificationFailed { reason }) => {
                assert!(reason.contains("BadChainLink"), "reason names the link: {reason}");
            }
            other => panic!("expected a chain-link refusal, got {other:?}"),
        }
        // Garbage is a decode refusal, not a panic.
        assert!(matches!(
            certificate_summary(vec![1, 2, 3]),
            Err(LightCoreError::BadCertificate { .. })
        ));
        // The embedded testnet root is a full ML-DSA public key.
        assert_eq!(testnet_root_public_key().len(), 2592);
    }

    #[test]
    fn detection_book_scans_a_tag_stream_and_persists() {
        let book = DetectionBook::new();
        book.add_contact("alice".into(), vec![0xA1u8; 32]).unwrap();
        assert!(book.add_contact("short".into(), vec![1u8; 8]).is_err());
        // A relayed stream: noise, then alice's counters 0,1
        // at epoch 10 and counter 2 at epoch 11.
        let mut stream = Vec::new();
        for n in 0..100u64 {
            stream.extend_from_slice(&poe_wallet::det_tag(&[0x77u8; 32], n, 10).to_bytes());
        }
        for (i, e) in [(0u64, 10u64), (1, 10), (2, 11)] {
            stream.extend_from_slice(&poe_wallet::det_tag(&[0xA1u8; 32], i, e).to_bytes());
        }
        let hits = book.scan(stream.clone(), 10, 11, 8).unwrap();
        assert_eq!(
            hits.iter().map(|h| (h.counter, h.epoch)).collect::<Vec<_>>(),
            vec![(0, 10), (1, 10), (2, 11)]
        );
        assert_eq!(book.next_counter("alice".into()), Some(3));
        // Custody round-trip: the restored book does not
        // re-match settled tags.
        let restored = DetectionBook::from_state(book.export_state()).unwrap();
        assert_eq!(restored.next_counter("alice".into()), Some(3));
        assert!(restored.scan(stream, 10, 11, 8).unwrap().is_empty());
        // A ragged stream is refused, not truncated.
        assert!(book.scan(vec![0u8; 10], 10, 11, 8).is_err());
    }
}
