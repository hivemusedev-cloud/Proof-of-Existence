//! poe-finality — ordering's other half (BUILD_FLOW Step 4).
//!
//! * **Round beacons** are hashes of the DAG's past: `H(domain, ref, round)`
//!   over a finalized reference block (see [`Finality::beacon`]),
//!   domain-separated per purpose.
//! * **Proposals**: a machine may propose in a round only if its hash-chain
//!   ticket, drawn against the round's proposal beacon, wins the manual's
//!   `16/A` rule (Step 2's tickets, verified here against the committed
//!   chain — the reveal is checked, never trusted). One block per
//!   `(machine, round)` is a claim under the kernel's one law: the second
//!   proposal is **evidence**, and its author is revoked.
//! * **Committees are sampled by tickets** the same way, against the
//!   committee beacon, with a target size ([`COMMITTEE_TARGET`]); at or
//!   below the target, every active machine sits.
//! * **Votes** are XMSS one-time signatures (Step 2's keys) over the block
//!   id, one per `(machine, round)` under the same law — a second vote for
//!   a different side is **evidence** and revokes. A block is **final**
//!   when more than two thirds of the round's committee have voted for it.
//! * **Heartbeats**: at each epoch a machine is credited iff it cast every
//!   vote it owed (its committee rounds) and stands unrevoked — the
//!   crediting rule the money engine's vesting consumes.

use poe_crypto::hash::{h, Part, H512};
use poe_crypto::pq;
use poe_crypto::tickets::{ticket_score, verify_reveal};
use poe_crypto::xmss::{self, XmssSignature, H32};
use poe_dag::{Block, BlockId, Dag};
use poe_kernel::{ClaimOutcome, Registry, RegistryKind, Spend};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Expected committee size when the active set is larger.
pub const COMMITTEE_TARGET: u64 = 32;

/// The side a claim names: the first word of the block id.
pub fn side_of(id: &BlockId) -> u64 {
    u64::from_be_bytes(id[..8].try_into().expect("64-byte id"))
}

/// The ticket win rule generalized: `score` wins a draw of expected size
/// `target` among `active` machines iff it falls below `target/active` of
/// the range. (The proposal draw is this with target 16.)
pub fn draw_wins(score: u64, target: u64, active: u64) -> bool {
    if active == 0 || target == 0 {
        return false;
    }
    if target >= active {
        return true;
    }
    (score as u128) < (target as u128) * (1u128 << 64) / (active as u128)
}

/// What a node must know about a machine to verify its work: its vote
/// key's root and height, its ticket chain's commitment, its identity
/// (ML-DSA) public key. All public, all registered before the machine acts.
#[derive(Clone)]
pub struct MachineInfo {
    pub xmss_root: H32,
    pub xmss_height: u32,
    pub chain_commitment: H512,
    pub dsa_public_key: Vec<u8>,
}

/// One committee vote: an XMSS one-time signature over a block id, plus
/// the ticket link that seated the voter (already revealed in the round's
/// reveal phase, carried here for stateless verifiers).
#[derive(Clone)]
pub struct Vote {
    pub machine: u64,
    pub round: u64,
    pub block: BlockId,
    pub sig: XmssSignature,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FinError {
    UnknownMachine,
    Revoked,
    BadReveal,
    NotProposer,
    NotCommittee,
    RoundNotClosed,
    UnknownBlock,
    BadSignature,
    LeafReuse,
    HeartbeatBad,
}

pub struct Finality {
    pub dag: Dag,
    machines: BTreeMap<u64, MachineInfo>,
    /// Ticket links revealed per (round, machine).
    reveals: HashMap<(u64, u64), H512>,
    committees: HashMap<u64, Vec<u64>>,
    prop_regs: HashMap<u64, Registry>,
    vote_regs: HashMap<u64, Registry>,
    canonical_prop: HashMap<(u64, u64), BlockId>,
    canonical_vote: HashMap<(u64, u64), BlockId>,
    voters: HashMap<(u64, BlockId), HashSet<u64>>,
    used_leaves: HashMap<u64, HashSet<u64>>,
    pub finalized: HashMap<u64, BlockId>,
    pub prop_evidence: Vec<(u64, u64, BlockId, BlockId)>, // machine, round, canonical, offender
    pub vote_evidence: Vec<(u64, u64, BlockId, BlockId)>,
    revoked: HashMap<u64, u64>, // machine -> epoch of revocation
    owed: HashMap<(u64, u64), u64>,
    cast: HashMap<(u64, u64), u64>,
    pub rounds_per_epoch: u64,
}

impl Finality {
    pub fn new(k: u64, rounds_per_epoch: u64) -> Finality {
        Finality {
            dag: Dag::new(k),
            machines: BTreeMap::new(),
            reveals: HashMap::new(),
            committees: HashMap::new(),
            prop_regs: HashMap::new(),
            vote_regs: HashMap::new(),
            canonical_prop: HashMap::new(),
            canonical_vote: HashMap::new(),
            voters: HashMap::new(),
            used_leaves: HashMap::new(),
            finalized: HashMap::new(),
            prop_evidence: Vec::new(),
            vote_evidence: Vec::new(),
            revoked: HashMap::new(),
            owed: HashMap::new(),
            cast: HashMap::new(),
            rounds_per_epoch,
        }
    }

    pub fn register_machine(&mut self, id: u64, info: MachineInfo) {
        self.prop_regs.insert(id, Registry::new(RegistryKind::Proposal));
        self.vote_regs.insert(id, Registry::new(RegistryKind::Vote));
        self.machines.insert(id, info);
    }

    pub fn is_revoked(&self, machine: u64) -> bool {
        self.revoked.contains_key(&machine)
    }

    pub fn active_count(&self) -> u64 {
        self.machines.keys().filter(|m| !self.revoked.contains_key(m)).count() as u64
    }

    pub fn epoch_of(&self, round: u64) -> u64 {
        round / self.rounds_per_epoch
    }

    /// A round beacon: a hash of the DAG's past and the round, under a
    /// purpose domain. The past it names is the FINALIZED block of the
    /// round two back — a fixed point every honest node holds identically
    /// once that round is final — or, for rounds 0 and 1, the genesis
    /// block. (Live-network correction, 2026-11-13: the first reading
    /// hashed the node's current selected tip, which changes with every
    /// block a node happens to have received, so two honest nodes sampled
    /// different committees and refused each other's proposals; the chain
    /// could not converge outside lockstep. A finalized reference is the
    /// only reading of "the DAG's past" that is a function of the chain
    /// rather than of message arrival order.)
    pub fn beacon(&self, domain: &str, round: u64) -> H512 {
        let reference = self.beacon_reference(round);
        h(domain, &[Part::Bytes(&reference), Part::Nat(round)])
    }

    /// The beacon's reference block for `round`: the finalized block of
    /// round `round - 2` when there is one, else the genesis block (the
    /// unique parentless round-0 block), else zero.
    pub fn beacon_reference(&self, round: u64) -> BlockId {
        if round >= 2 {
            if let Some(b) = self.finalized.get(&(round - 2)) {
                return *b;
            }
        }
        self.dag
            .blocks()
            .into_iter()
            .find(|b| b.round == 0 && b.parents.is_empty())
            .map(|b| b.id)
            .unwrap_or([0u8; 64])
    }

    fn draw_link(&self, machine: u64, round: u64) -> Option<H512> {
        self.reveals.get(&(round, machine)).copied()
    }

    /// The reveal phase: a machine shows the ticket link for `round`
    /// (chain step `round + 1`). Verified against the committed chain tip —
    /// a link that does not hash forward to the commitment is refused.
    pub fn submit_reveal(&mut self, machine: u64, round: u64, link: H512) -> Result<(), FinError> {
        let info = self.machines.get(&machine).ok_or(FinError::UnknownMachine)?;
        if self.is_revoked(machine) {
            return Err(FinError::Revoked);
        }
        if !verify_reveal(&info.chain_commitment, (round + 1) as usize, &link) {
            return Err(FinError::BadReveal);
        }
        self.reveals.insert((round, machine), link);
        Ok(())
    }

    /// Close the round's reveal phase: sample the committee by ticket and
    /// record what each member now owes. Idempotent per round.
    pub fn close_round_reveals(&mut self, round: u64) -> &[u64] {
        if !self.committees.contains_key(&round) {
            let beacon = self.beacon("beacon-comm", round);
            let active = self.active_count();
            let mut members: Vec<u64> = self
                .machines
                .keys()
                .copied()
                .filter(|m| !self.is_revoked(*m))
                .filter(|m| match self.draw_link(*m, round) {
                    Some(link) => {
                        draw_wins(ticket_score(&beacon, &link), COMMITTEE_TARGET, active)
                    }
                    None => false,
                })
                .collect();
            members.sort_unstable();
            for m in &members {
                *self.owed.entry((*m, self.epoch_of(round))).or_insert(0) += 1;
            }
            self.committees.insert(round, members);
        }
        &self.committees[&round]
    }

    pub fn committee(&self, round: u64) -> Option<&[u64]> {
        self.committees.get(&round).map(|v| v.as_slice())
    }

    /// Diagnostic: the votes counted so far for `round`, as
    /// (block, distinct voters), sorted by block id.
    pub fn vote_tally(&self, round: u64) -> Vec<(BlockId, u64)> {
        let mut out: Vec<(BlockId, u64)> = self
            .voters
            .iter()
            .filter(|((r, _), _)| *r == round)
            .map(|((_, b), s)| (*b, s.len() as u64))
            .collect();
        out.sort_unstable();
        out
    }

    /// Offer a proposal block. The proposer's ticket must win the `16/A`
    /// draw against the proposal beacon; the block enters the DAG; the
    /// one-law claim decides canonical vs evidence.
    pub fn propose(&mut self, block: Block) -> Result<ClaimOutcome, FinError> {
        let machine = block.machine;
        let round = block.round;
        if !self.machines.contains_key(&machine) {
            return Err(FinError::UnknownMachine);
        }
        if self.is_revoked(machine) {
            return Err(FinError::Revoked);
        }
        let link = self.draw_link(machine, round).ok_or(FinError::BadReveal)?;
        let beacon = self.beacon("beacon-prop", round);
        if !draw_wins(ticket_score(&beacon, &link), 16, self.active_count()) {
            return Err(FinError::NotProposer);
        }
        match self.dag.insert(block.clone()) {
            Ok(()) | Err(poe_dag::DagError::Duplicate) => {}
            Err(e) => panic!("dag refused a proposal: {e:?}"),
        }
        let outcome = self
            .prop_regs
            .get_mut(&machine)
            .expect("registered")
            .claim(Spend { tx: side_of(&block.id), nf: round });
        match outcome {
            ClaimOutcome::Accepted => {
                self.canonical_prop.insert((machine, round), block.id);
            }
            ClaimOutcome::Evidence => {
                let canonical = self.canonical_prop[&(machine, round)];
                self.prop_evidence.push((machine, round, canonical, block.id));
                self.revoke(machine, round);
            }
            ClaimOutcome::Duplicate => {}
        }
        Ok(outcome)
    }

    /// Cast a committee vote. Verified in order: the voter sits on the
    /// round's committee, the signature verifies against the machine's
    /// XMSS root, the leaf has never been used by this machine before —
    /// then the one law decides accepted / duplicate / evidence.
    pub fn vote(&mut self, vote: Vote) -> Result<ClaimOutcome, FinError> {
        let machine = vote.machine;
        let info = self.machines.get(&machine).ok_or(FinError::UnknownMachine)?.clone();
        if self.is_revoked(machine) {
            return Err(FinError::Revoked);
        }
        let (is_member, committee_size) = {
            let committee = self.committees.get(&vote.round).ok_or(FinError::RoundNotClosed)?;
            (committee.contains(&machine), committee.len() as u64)
        };
        if !is_member {
            return Err(FinError::NotCommittee);
        }
        match self.dag.get(&vote.block) {
            Some(b) if b.round == vote.round => {}
            _ => return Err(FinError::UnknownBlock),
        }
        if !xmss::verify(&info.xmss_root, info.xmss_height, &vote.block, &vote.sig) {
            return Err(FinError::BadSignature);
        }
        if !self.used_leaves.entry(machine).or_default().insert(vote.sig.leaf) {
            return Err(FinError::LeafReuse);
        }
        let outcome = self
            .vote_regs
            .get_mut(&machine)
            .expect("registered")
            .claim(Spend { tx: side_of(&vote.block), nf: vote.round });
        match outcome {
            ClaimOutcome::Accepted => {
                self.canonical_vote.insert((machine, vote.round), vote.block);
                self.voters.entry((vote.round, vote.block)).or_default().insert(machine);
                *self.cast.entry((machine, self.epoch_of(vote.round))).or_insert(0) += 1;
                let count = self.voters[&(vote.round, vote.block)].len() as u64;
                if count * 3 > 2 * committee_size && !self.finalized.contains_key(&vote.round) {
                    self.finalized.insert(vote.round, vote.block);
                }
            }
            ClaimOutcome::Evidence => {
                let canonical = self.canonical_vote[&(machine, vote.round)];
                self.vote_evidence.push((machine, vote.round, canonical, vote.block));
                self.revoke(machine, vote.round);
            }
            ClaimOutcome::Duplicate => {}
        }
        Ok(outcome)
    }

    fn revoke(&mut self, machine: u64, at_round: u64) {
        self.revoked.insert(machine, self.epoch_of(at_round));
    }

    /// The epoch heartbeat message a machine signs with its identity key:
    /// a hash of the epoch and the finalized tip it ends on.
    pub fn heartbeat_message(&self, epoch: u64) -> H512 {
        let last_round = (epoch + 1) * self.rounds_per_epoch - 1;
        let tip = self.finalized.get(&last_round).copied().unwrap_or([0u8; 64]);
        h("heartbeat", &[Part::Nat(epoch), Part::Bytes(&tip)])
    }

    /// Verify a signed heartbeat for an epoch.
    pub fn verify_heartbeat(&self, machine: u64, epoch: u64, sig: &[u8]) -> Result<(), FinError> {
        let info = self.machines.get(&machine).ok_or(FinError::UnknownMachine)?;
        let msg = self.heartbeat_message(epoch);
        if pq::dsa_verify(&info.dsa_public_key, &msg, sig) {
            Ok(())
        } else {
            Err(FinError::HeartbeatBad)
        }
    }

    /// The crediting rule: an epoch credits a machine iff it cast every
    /// vote it owed and was not revoked in or before that epoch.
    pub fn heartbeat_credited(&self, machine: u64, epoch: u64) -> bool {
        if let Some(&rev_epoch) = self.revoked.get(&machine) {
            if rev_epoch <= epoch {
                return false;
            }
        }
        let owed = self.owed.get(&(machine, epoch)).copied().unwrap_or(0);
        let cast = self.cast.get(&(machine, epoch)).copied().unwrap_or(0);
        owed > 0 && cast == owed
    }
}

// -- Wire encodings (the gossip payload formats) -----------------------------

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_bytes32s(out: &mut Vec<u8>, xs: &[H32]) {
    out.extend_from_slice(&(xs.len() as u32).to_be_bytes());
    for x in xs {
        out.extend_from_slice(x);
    }
}

struct Reader<'a> {
    raw: &'a [u8],
    off: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.off.checked_add(n)?;
        let s = self.raw.get(self.off..end)?;
        self.off = end;
        Some(s)
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }
    fn bytes32s(&mut self) -> Option<Vec<H32>> {
        let n = u32::from_be_bytes(self.take(4)?.try_into().ok()?) as usize;
        if n > 4096 {
            return None;
        }
        let mut xs = Vec::with_capacity(n);
        for _ in 0..n {
            xs.push(self.take(32)?.try_into().ok()?);
        }
        Some(xs)
    }
}

/// Canonical vote encoding: machine, round, block id, then the XMSS
/// signature (leaf, WOTS+ chain values, authentication path).
pub fn encode_vote(v: &Vote) -> Vec<u8> {
    let mut out = Vec::new();
    put_u64(&mut out, v.machine);
    put_u64(&mut out, v.round);
    out.extend_from_slice(&v.block);
    put_u64(&mut out, v.sig.leaf);
    put_bytes32s(&mut out, &v.sig.wots);
    put_bytes32s(&mut out, &v.sig.auth);
    out
}

pub fn decode_vote(raw: &[u8]) -> Option<Vote> {
    let mut r = Reader { raw, off: 0 };
    let machine = r.u64()?;
    let round = r.u64()?;
    let block: BlockId = r.take(64)?.try_into().ok()?;
    let leaf = r.u64()?;
    let wots = r.bytes32s()?;
    let auth = r.bytes32s()?;
    Some(Vote { machine, round, block, sig: XmssSignature { leaf, wots, auth } })
}

/// Canonical machine-announcement encoding: everything a peer needs to
/// register the machine — its attestation (device key, root, serial,
/// expiry, root signature) and its finality material (XMSS root and
/// height, ticket-chain commitment). The identity key doubles as the
/// device key, so it appears once.
#[derive(Clone)]
pub struct Announcement {
    pub device_pk: Vec<u8>,
    pub root_id: u64,
    pub serial: u64,
    pub expiry_epoch: u64,
    pub root_signature: Vec<u8>,
    pub xmss_root: H32,
    pub xmss_height: u32,
    pub chain_commitment: H512,
}

pub fn encode_announcement(a: &Announcement) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(a.device_pk.len() as u32).to_be_bytes());
    out.extend_from_slice(&a.device_pk);
    put_u64(&mut out, a.root_id);
    put_u64(&mut out, a.serial);
    put_u64(&mut out, a.expiry_epoch);
    out.extend_from_slice(&(a.root_signature.len() as u32).to_be_bytes());
    out.extend_from_slice(&a.root_signature);
    out.extend_from_slice(&a.xmss_root);
    out.extend_from_slice(&a.xmss_height.to_be_bytes());
    out.extend_from_slice(&a.chain_commitment);
    out
}

pub fn decode_announcement(raw: &[u8]) -> Option<Announcement> {
    let mut r = Reader { raw, off: 0 };
    let pk_len = u32::from_be_bytes(r.take(4)?.try_into().ok()?) as usize;
    if pk_len > 8192 {
        return None;
    }
    let device_pk = r.take(pk_len)?.to_vec();
    let root_id = r.u64()?;
    let serial = r.u64()?;
    let expiry_epoch = r.u64()?;
    let sig_len = u32::from_be_bytes(r.take(4)?.try_into().ok()?) as usize;
    if sig_len > 8192 {
        return None;
    }
    let root_signature = r.take(sig_len)?.to_vec();
    let xmss_root: H32 = r.take(32)?.try_into().ok()?;
    let xmss_height = u32::from_be_bytes(r.take(4)?.try_into().ok()?);
    let chain_commitment: H512 = r.take(64)?.try_into().ok()?;
    Some(Announcement {
        device_pk,
        root_id,
        serial,
        expiry_epoch,
        root_signature,
        xmss_root,
        xmss_height,
        chain_commitment,
    })
}

// -- State snapshot / restore (epoch-boundary sync for late joiners) --------

/// The part of a node's finality state a late joiner needs at an epoch
/// boundary, when every past round is finalized: who the machines are,
/// who stands revoked, which XMSS leaves are burned, what is final, and
/// the DAG itself. Per-round working state (reveals, committees, claim
/// registries, owed/cast counters) is NOT carried: claims and counters
/// are per-round and per-epoch, so for every future round a restored
/// node starts exactly where a node that never left starts.
pub struct FinalitySnapshot {
    pub k: u64,
    pub rounds_per_epoch: u64,
    pub machines: Vec<(u64, MachineInfo)>,
    pub revoked: Vec<(u64, u64)>,
    pub used_leaves: Vec<(u64, Vec<u64>)>,
    pub finalized: Vec<(u64, BlockId)>,
    pub dag_blocks: Vec<Block>,
}

impl Finality {
    pub fn snapshot(&self) -> FinalitySnapshot {
        FinalitySnapshot {
            k: self.dag.k,
            rounds_per_epoch: self.rounds_per_epoch,
            machines: self
                .machines
                .iter()
                .map(|(id, info)| (*id, info.clone()))
                .collect(),
            revoked: self.revoked.iter().map(|(m, e)| (*m, *e)).collect(),
            used_leaves: self
                .used_leaves
                .iter()
                .map(|(m, s)| (*m, s.iter().copied().collect()))
                .collect(),
            finalized: self.finalized.iter().map(|(r, b)| (*r, *b)).collect(),
            dag_blocks: self.dag.blocks(),
        }
    }

    pub fn restore(snap: FinalitySnapshot) -> Finality {
        let mut fin = Finality::new(snap.k, snap.rounds_per_epoch);
        for b in snap.dag_blocks {
            let _ = fin.dag.insert(b);
        }
        for (id, info) in snap.machines {
            fin.register_machine(id, info);
        }
        for (m, e) in snap.revoked {
            fin.revoked.insert(m, e);
        }
        for (m, leaves) in snap.used_leaves {
            fin.used_leaves.insert(m, leaves.into_iter().collect());
        }
        for (r, b) in snap.finalized {
            fin.finalized.insert(r, b);
        }
        fin
    }
}
