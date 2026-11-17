//! Finality certificates — light-duty protocol addition #1
//! (POE_LIGHT_DUTY_DESIGN.md §4; spec: PoE_Certificates.lean in the
//! Lean extension tree).
//!
//! A certificate packages one epoch's finality as portable evidence:
//! the epoch's closing round, the block that round finalized, the
//! state roots chaining this epoch to the previous one, and the
//! evidence itself — the announcement set, the closing round's ticket
//! reveals, and the votes for the named block. [`verify_certificate`]
//! checks the evidence from scratch, with no DAG and no ledger,
//! exactly as the design note specifies: announcements against the
//! root key, the committee recomputed from the reveals exactly as
//! [`Finality::close_round_reveals`] draws it, each vote's XMSS
//! signature against its voter's announced root, and the count
//! against the protocol's own rule (more than two thirds of the drawn
//! committee). On success the certificate's `state_root` and `minted`
//! are accepted as the epoch's facts (design note §4, step 5).
//!
//! Soundness, stated and proved in PoE_Certificates.lean at the
//! kernel's Part B abstraction: two certificates for one round naming
//! different blocks name more than a third of the committee as double
//! voters, and below a third of double actors conflicting
//! certificates never both verify.
//!
//! Honest boundaries of this first build:
//! * A closing round that finalized as a **null round** (skip
//!   attestation) has no votes for its block; emission returns `None`
//!   for such an epoch and verification refuses a null close block.
//!   Null-round certificates are a second evidence shape, not built.
//! * The `revoked` list is asserted by the emitting node (the one
//!   field not self-evidencing in the format). It is monotone across
//!   the certificate chain — a later certificate's list extends every
//!   earlier one an honest node issued — and a light client holding
//!   certificates from two sources sees any disagreement at the first
//!   divergent epoch. Every other field is checked from evidence.
//! * Announcement verification checks the root signature, the
//!   machine-id binding, and liveness at the certificate's epoch. The
//!   fuller registry policy (root admission sets, join quotas, clone
//!   bindings) stays with poe-identity at registration time; a
//!   certificate verifier pins the one root key it trusts.

use crate::{
    draw_wins, encode_announcement, encode_vote, decode_announcement, decode_vote,
    Announcement, BlockId, Finality, Vote, COMMITTEE_TARGET, NULL_BLOCK,
};
use poe_crypto::hash::{h, Part, H512};
use poe_crypto::pq::dsa_verify;
use poe_crypto::tickets::{ticket_score, verify_reveal};
use poe_crypto::xmss;
use std::collections::{BTreeMap, HashSet};

/// The certificate wire format's magic and version.
pub const CERT_MAGIC: &[u8; 8] = b"POECERT1";

/// One epoch's finality certificate. See the module docs.
#[derive(Clone)]
pub struct Certificate {
    pub epoch: u64,
    /// The store's state root after the previous epoch's close.
    pub prev_state_root: H512,
    /// The store's state root after this epoch's close.
    pub state_root: H512,
    /// The Merkle companion root after this epoch's close
    /// (poe-store's `merkle` module, addition #2): the root a
    /// light client checks its own notes' paths against.
    pub companion_root: H512,
    /// Total minted after this epoch's close.
    pub minted: u128,
    /// The epoch's last round: `(epoch + 1) * rounds_per_epoch - 1`.
    pub close_round: u64,
    /// The finalized block of `close_round` (never [`NULL_BLOCK`] in
    /// this evidence shape).
    pub close_block: BlockId,
    /// The beacon reference the closing round's committee was drawn
    /// against: the finalized block of `close_round - 2`, or the
    /// genesis/zero fallback of [`Finality::beacon_reference`].
    pub beacon_reference: BlockId,
    /// The announcement set the closing round's machines registered
    /// under, sorted by machine id.
    pub announcements: Vec<(u64, Announcement)>,
    /// `H` of the announcement set, as [`announcements_hash`] computes.
    pub announcements_hash: H512,
    /// Machines revoked at or before this epoch, sorted. Asserted by
    /// the emitter; see the module docs.
    pub revoked: Vec<u64>,
    /// The closing round's ticket reveals, sorted by machine id.
    pub reveals: Vec<(u64, H512)>,
    /// The closing round's accepted votes for `close_block`.
    pub votes: Vec<Vote>,
}

/// Why a certificate does not verify. Each variant is a refusal, in
/// the order [`verify_certificate`] checks them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertError {
    /// `prev_state_root` is not the root the verifier last accepted.
    BadChainLink,
    /// A closing round that closed empty has no certificate in this
    /// evidence shape.
    NullClose,
    /// The announcement list is not strictly increasing by machine.
    BadAnnouncementSet,
    /// An announcement's machine id is not the id of its device key.
    MachineIdMismatch,
    /// An announcement's root signature does not verify.
    BadAnnouncementSignature,
    /// An announcement expired at or before the certificate's epoch.
    AnnouncementExpired,
    /// The set's hash is not the certificate's `announcements_hash`.
    BadAnnouncementHash,
    /// The revoked list is not strictly increasing.
    BadRevokedSet,
    /// The reveal list is not strictly increasing by machine.
    BadRevealSet,
    /// A reveal or vote names a machine with no announcement.
    UnknownMachine,
    /// A reveal does not hash forward to the machine's commitment.
    BadReveal,
    /// A vote is for another round.
    VoteRoundMismatch,
    /// A vote is for another block.
    VoteBlockMismatch,
    /// A vote's author is not in the recomputed committee.
    NotCommittee,
    /// A vote's XMSS signature does not verify.
    BadVoteSignature,
    /// The votes are not more than two thirds of the committee.
    NoQuorum,
}

/// A device's machine id, derived from its public key. Mirrors
/// `poe_identity::device_id` byte for byte (poe-finality does not
/// depend on poe-identity; the node's tests pin the two together).
pub fn device_id_of(device_pk: &[u8]) -> u64 {
    h("device-id", &[Part::Bytes(device_pk)])[0..8]
        .try_into()
        .map(u64::from_be_bytes)
        .unwrap_or(0)
}

/// The bytes a root signs to attest a device. Mirrors
/// `poe_identity::Attestation::statement` for the announcement's
/// attestation fields.
pub fn announcement_statement(a: &Announcement) -> H512 {
    h(
        "attestation",
        &[
            Part::Bytes(&a.device_pk),
            Part::Nat(a.root_id),
            Part::Nat(a.serial),
            Part::Nat(a.expiry_epoch),
        ],
    )
}

/// The announcement set's hash: a domain-separated hash of the
/// set's members in machine order, each as its id followed by its
/// canonical encoding.
pub fn announcements_hash(set: &[(u64, Announcement)]) -> H512 {
    let mut buf = Vec::new();
    for (m, a) in set {
        buf.extend_from_slice(&m.to_be_bytes());
        buf.extend_from_slice(&encode_announcement(a));
    }
    h("cert-announcements", &[Part::Bytes(&buf)])
}

impl Finality {
    /// Emit the certificate for `epoch` from this node's finality
    /// state, or `None` when the epoch has none in this evidence
    /// shape: its closing round is not finalized here, or it
    /// finalized as a null round, or its votes do not reach quorum
    /// against the committee this node drew (an emitter never issues
    /// a certificate its own evidence cannot carry).
    ///
    /// `prev_state_root` / `state_root` / `companion_root` /
    /// `minted` are the store's facts for the close (the caller
    /// reads them from poe-store); `announcements` is the node's
    /// full announcement set.
    pub fn certificate(
        &self,
        epoch: u64,
        prev_state_root: H512,
        state_root: H512,
        companion_root: H512,
        minted: u128,
        announcements: &BTreeMap<u64, Announcement>,
    ) -> Option<Certificate> {
        let close_round = (epoch + 1)
            .checked_mul(self.rounds_per_epoch)
            .and_then(|n| n.checked_sub(1))?;
        let close_block = *self.finalized.get(&close_round)?;
        if close_block == NULL_BLOCK {
            return None;
        }
        let committee = self.committees.get(&close_round)?;
        let mut reveals: Vec<(u64, H512)> = self
            .reveals
            .iter()
            .filter(|((r, _), _)| *r == close_round)
            .map(|((_, m), link)| (*m, *link))
            .collect();
        reveals.sort_by_key(|(m, _)| *m);
        let votes: Vec<Vote> = self
            .votes_in_round(close_round)
            .into_iter()
            .filter(|v| v.block == close_block)
            .collect();
        let voters: HashSet<u64> = votes.iter().map(|v| v.machine).collect();
        if voters.len() as u64 * 3 <= 2 * committee.len() as u64 {
            return None;
        }
        let mut revoked: Vec<u64> = self
            .revoked
            .iter()
            .filter(|(_, e)| **e <= epoch)
            .map(|(m, _)| *m)
            .collect();
        revoked.sort_unstable();
        let set: Vec<(u64, Announcement)> =
            announcements.iter().map(|(m, a)| (*m, a.clone())).collect();
        Some(Certificate {
            epoch,
            prev_state_root,
            state_root,
            companion_root,
            minted,
            close_round,
            close_block,
            beacon_reference: self.beacon_reference(close_round),
            announcements_hash: announcements_hash(&set),
            announcements: set,
            revoked,
            reveals,
            votes,
        })
    }
}

/// Verify a certificate from its evidence alone. `root_pk` is the
/// attestation root the verifier pins (the testnet root on the
/// testnet; a manufacturer's root at mainnet); `expected_prev_root`
/// is the state root of the last certificate the verifier accepted
/// (the genesis root for the first). See the module docs for what is
/// checked, and for the one asserted field (`revoked`).
pub fn verify_certificate(
    cert: &Certificate,
    root_pk: &[u8],
    expected_prev_root: &H512,
) -> Result<(), CertError> {
    if cert.prev_state_root != *expected_prev_root {
        return Err(CertError::BadChainLink);
    }
    if cert.close_block == NULL_BLOCK {
        return Err(CertError::NullClose);
    }
    // The announcement set: sorted, bound to its keys, root-signed,
    // live at the certificate's epoch, and hashed as named.
    let mut infos: BTreeMap<u64, &Announcement> = BTreeMap::new();
    for (i, (machine, a)) in cert.announcements.iter().enumerate() {
        if i > 0 && cert.announcements[i - 1].0 >= *machine {
            return Err(CertError::BadAnnouncementSet);
        }
        if device_id_of(&a.device_pk) != *machine {
            return Err(CertError::MachineIdMismatch);
        }
        if !dsa_verify(root_pk, &announcement_statement(a), &a.root_signature) {
            return Err(CertError::BadAnnouncementSignature);
        }
        if a.expiry_epoch <= cert.epoch {
            return Err(CertError::AnnouncementExpired);
        }
        infos.insert(*machine, a);
    }
    if announcements_hash(&cert.announcements) != cert.announcements_hash {
        return Err(CertError::BadAnnouncementHash);
    }
    for i in 1..cert.revoked.len() {
        if cert.revoked[i - 1] >= cert.revoked[i] {
            return Err(CertError::BadRevokedSet);
        }
    }
    let revoked: HashSet<u64> = cert.revoked.iter().copied().collect();
    // The closing round's reveals, each checked against its machine's
    // committed chain exactly as `submit_reveal` checks it.
    let mut links: BTreeMap<u64, H512> = BTreeMap::new();
    for (i, (machine, link)) in cert.reveals.iter().enumerate() {
        if i > 0 && cert.reveals[i - 1].0 >= *machine {
            return Err(CertError::BadRevealSet);
        }
        let a = infos.get(machine).ok_or(CertError::UnknownMachine)?;
        if !verify_reveal(&a.chain_commitment, (cert.close_round + 1) as usize, link) {
            return Err(CertError::BadReveal);
        }
        links.insert(*machine, *link);
    }
    // The committee, recomputed exactly as `close_round_reveals`
    // draws it: the round's beacon over its finalized reference, the
    // reveal count as the draw denominator, target COMMITTEE_TARGET.
    let beacon = h(
        "beacon-comm",
        &[Part::Bytes(&cert.beacon_reference), Part::Nat(cert.close_round)],
    );
    let active = cert.reveals.len() as u64;
    let mut committee: HashSet<u64> = HashSet::new();
    for machine in infos.keys() {
        if revoked.contains(machine) {
            continue;
        }
        if let Some(link) = links.get(machine) {
            if draw_wins(ticket_score(&beacon, link), COMMITTEE_TARGET, active) {
                committee.insert(*machine);
            }
        }
    }
    // The votes: for this round and block, from committee members,
    // each signature verified against the voter's announced root.
    let mut voters: HashSet<u64> = HashSet::new();
    for v in &cert.votes {
        if v.round != cert.close_round {
            return Err(CertError::VoteRoundMismatch);
        }
        if v.block != cert.close_block {
            return Err(CertError::VoteBlockMismatch);
        }
        let a = infos.get(&v.machine).ok_or(CertError::UnknownMachine)?;
        if !committee.contains(&v.machine) {
            return Err(CertError::NotCommittee);
        }
        if !xmss::verify(&a.xmss_root, a.xmss_height, &v.block, &v.sig) {
            return Err(CertError::BadVoteSignature);
        }
        voters.insert(v.machine);
    }
    if committee.is_empty() || voters.len() as u64 * 3 <= 2 * committee.len() as u64 {
        return Err(CertError::NoQuorum);
    }
    Ok(())
}

// -- Wire format --------------------------------------------------------------

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Encode a certificate for storage or serving. The format is
/// [`CERT_MAGIC`] followed by the fields in declaration order;
/// variable-length members are length-prefixed and members are
/// carried in their canonical encodings (announcements and votes use
/// this crate's own codecs).
pub fn encode_certificate(c: &Certificate) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(CERT_MAGIC);
    put_u64(&mut out, c.epoch);
    out.extend_from_slice(&c.prev_state_root);
    out.extend_from_slice(&c.state_root);
    out.extend_from_slice(&c.companion_root);
    out.extend_from_slice(&c.minted.to_be_bytes());
    put_u64(&mut out, c.close_round);
    out.extend_from_slice(&c.close_block);
    out.extend_from_slice(&c.beacon_reference);
    out.extend_from_slice(&c.announcements_hash);
    put_u32(&mut out, c.announcements.len() as u32);
    for (m, a) in &c.announcements {
        put_u64(&mut out, *m);
        let enc = encode_announcement(a);
        put_u32(&mut out, enc.len() as u32);
        out.extend_from_slice(&enc);
    }
    put_u32(&mut out, c.revoked.len() as u32);
    for m in &c.revoked {
        put_u64(&mut out, *m);
    }
    put_u32(&mut out, c.reveals.len() as u32);
    for (m, link) in &c.reveals {
        put_u64(&mut out, *m);
        out.extend_from_slice(link);
    }
    put_u32(&mut out, c.votes.len() as u32);
    for v in &c.votes {
        let enc = encode_vote(v);
        put_u32(&mut out, enc.len() as u32);
        out.extend_from_slice(&enc);
    }
    out
}

struct Cursor<'a> {
    raw: &'a [u8],
    off: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.off.checked_add(n)?;
        let s = self.raw.get(self.off..end)?;
        self.off = end;
        Some(s)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }
    fn hash(&mut self) -> Option<H512> {
        self.take(64)?.try_into().ok()
    }
    fn count(&mut self) -> Option<usize> {
        let n = self.u32()? as usize;
        if n > 100_000 {
            return None;
        }
        Some(n)
    }
}

/// Decode a certificate written by [`encode_certificate`]. Trailing
/// bytes are refused: the format is versioned by its magic, and a
/// longer encoding is a different version, not a longer v1.
pub fn decode_certificate(raw: &[u8]) -> Option<Certificate> {
    let mut r = Cursor { raw, off: 0 };
    if r.take(8)? != CERT_MAGIC {
        return None;
    }
    let epoch = r.u64()?;
    let prev_state_root = r.hash()?;
    let state_root = r.hash()?;
    let companion_root = r.hash()?;
    let minted = u128::from_be_bytes(r.take(16)?.try_into().ok()?);
    let close_round = r.u64()?;
    let close_block: BlockId = r.take(64)?.try_into().ok()?;
    let beacon_reference: BlockId = r.take(64)?.try_into().ok()?;
    let announcements_hash = r.hash()?;
    let n_ann = r.count()?;
    let mut announcements = Vec::with_capacity(n_ann);
    for _ in 0..n_ann {
        let m = r.u64()?;
        let len = r.u32()? as usize;
        let a = decode_announcement(r.take(len)?)?;
        announcements.push((m, a));
    }
    let n_rev = r.count()?;
    let mut revoked = Vec::with_capacity(n_rev);
    for _ in 0..n_rev {
        revoked.push(r.u64()?);
    }
    let n_links = r.count()?;
    let mut reveals = Vec::with_capacity(n_links);
    for _ in 0..n_links {
        let m = r.u64()?;
        reveals.push((m, r.hash()?));
    }
    let n_votes = r.count()?;
    let mut votes = Vec::with_capacity(n_votes);
    for _ in 0..n_votes {
        let len = r.u32()? as usize;
        votes.push(decode_vote(r.take(len)?)?);
    }
    if r.off != raw.len() {
        return None;
    }
    Some(Certificate {
        epoch,
        prev_state_root,
        state_root,
        companion_root,
        minted,
        close_round,
        close_block,
        beacon_reference,
        announcements,
        announcements_hash,
        revoked,
        reveals,
        votes,
    })
}
