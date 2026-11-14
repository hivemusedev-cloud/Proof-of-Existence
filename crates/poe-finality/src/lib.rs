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
    /// The draw denominator frozen for each closed round: how many
    /// machines had revealed for the round when it closed. Every
    /// draw for a round (committee, proposer) uses THIS number —
    /// never the live active count, which keeps changing as
    /// revocations and registrations land. With a live denominator,
    /// two nodes holding the same blocks can disagree on whether a
    /// block was a legitimate proposal, insert different subsets,
    /// and end up with different DAGs: consensus divergence from
    /// arrival order alone (found by the 100-machine simnet,
    /// 2026-11-14; invisible at 10 machines, where the draw always
    /// wins). Frozen at close, the denominator is a function of the
    /// round's closed reveal set, like the draws themselves.
    draw_base: HashMap<u64, u64>,
    prop_regs: HashMap<u64, Registry>,
    vote_regs: HashMap<u64, Registry>,
    canonical_prop: HashMap<(u64, u64), BlockId>,
    canonical_vote: HashMap<(u64, u64), BlockId>,
    voters: HashMap<(u64, BlockId), HashSet<u64>>,
    /// Accepted votes, retained so a node can re-serve them: a peer
    /// that synced from an epoch-boundary bundle still needs the
    /// current epoch's votes to finalize the rounds since the bundle,
    /// and gossip has no memory of its own. Bounded by
    /// [`Finality::prune_before`].
    vote_store: HashMap<(u64, u64), Vote>,
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
            draw_base: HashMap::new(),
            prop_regs: HashMap::new(),
            vote_regs: HashMap::new(),
            canonical_prop: HashMap::new(),
            canonical_vote: HashMap::new(),
            voters: HashMap::new(),
            vote_store: HashMap::new(),
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

    /// Machines that have revealed for `round` — the round's
    /// participant set, and the only denominator its draws may use.
    fn participants(&self, round: u64) -> u64 {
        self.reveals.keys().filter(|(r, _)| *r == round).count() as u64
    }

    /// The draw denominator for `round`: the participant count frozen
    /// when the round closed here, or — before the close — the
    /// participant count so far. A pre-close denominator is
    /// provisional (the reveal set is still gathering); the node's
    /// propose path treats pre-close NotProposer verdicts as
    /// retryable for exactly this reason.
    fn draw_denominator(&self, round: u64) -> u64 {
        self.draw_base
            .get(&round)
            .copied()
            .unwrap_or_else(|| self.participants(round))
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
            // Freeze the round's draw denominator NOW, from its
            // reveal set, and sample with it: after this close, no
            // revocation or registration may move the arithmetic of
            // this round's draws (see the draw_base field doc).
            let active = self.participants(round);
            self.draw_base.insert(round, active);
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

    /// A machine's revealed ticket link for `round`, if one was
    /// submitted here. Lets a node re-serve reveals to a peer that
    /// synced from a bundle and missed the collection window.
    pub fn reveal_of(&self, machine: u64, round: u64) -> Option<H512> {
        self.reveals.get(&(round, machine)).copied()
    }

    /// The accepted votes for `round` retained in the vote store,
    /// sorted by voter. See `vote_store` for why they are kept.
    pub fn votes_in_round(&self, round: u64) -> Vec<Vote> {
        let mut out: Vec<Vote> = self
            .vote_store
            .iter()
            .filter(|((_, r), _)| *r == round)
            .map(|(_, v)| v.clone())
            .collect();
        out.sort_by_key(|v| v.machine);
        out
    }

    /// Drop per-round working history (reveals, counted voters,
    /// stored votes) for rounds before `round`. Callers keep a
    /// bounded window — the current epoch plus slack — because that
    /// window is what bundle-synced peers still need re-served.
    pub fn prune_before(&mut self, round: u64) {
        self.reveals.retain(|(r, _), _| *r >= round);
        self.draw_base.retain(|r, _| *r >= round);
        self.voters.retain(|(r, _), _| *r >= round);
        self.vote_store.retain(|(_, r), _| *r >= round);
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
        if !draw_wins(ticket_score(&beacon, &link), 16, self.draw_denominator(round)) {
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
        // A vote can arrive before this node has closed the round's
        // committee (the close normally happens in the node's own
        // propose/vote step). If the round's beacon anchor is final
        // here, the committee is a deterministic function of the
        // stored reveals — close it now and judge the vote. If the
        // anchor is not final, closing would sample a divergent
        // committee: refuse, and the caller buffers the vote.
        if !self.committees.contains_key(&vote.round)
            && (vote.round < 2 || self.finalized.contains_key(&vote.round.saturating_sub(2)))
        {
            self.close_round_reveals(vote.round);
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
        // Fast path: a replay of the vote that already won this
        // claim is a Duplicate — the original was verified when it
        // was accepted, and a replay carries no new information.
        // Return before the signature check: re-served history
        // replays every accepted vote on every burst, and
        // re-verifying each one throttles a catching-up node below
        // chain speed.
        if let Some(reg) = self.vote_regs.get(&machine) {
            if reg.is_registered(vote.round)
                && poe_kernel::first_tx(reg.accepted(), vote.round) == side_of(&vote.block)
            {
                return Ok(ClaimOutcome::Duplicate);
            }
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
                self.vote_store.insert((machine, vote.round), vote.clone());
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
    /// Unsigned operational hint: the round this node synced from
    /// (0 for a genesis node). Peers use the smallest hint they have
    /// seen to know how far back their history re-service must reach
    /// for a catching-up joiner. Not part of the attestation.
    pub sync_hint: u64,
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
    put_u64(&mut out, a.sync_hint);
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
    // Trailing hint added after the first wire version; absent = 0.
    let sync_hint = r.u64().unwrap_or(0);
    Some(Announcement {
        device_pk,
        root_id,
        serial,
        expiry_epoch,
        root_signature,
        xmss_root,
        xmss_height,
        chain_commitment,
        sync_hint,
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

/// The base snapshot PLUS the live working state (committees,
/// reveals, retained votes, claim registries, vote counters) for
/// recent rounds. A bundle joiner does not need this — it rebuilds
/// working state from gossip — but a RESTARTED node does: without
/// it, the votes cast since the last epoch close exist nowhere once
/// every voter has restarted, and the frontier rounds can never
/// finalize. Written per-round to the node's own state file, never
/// shared. Working maps are filtered to rounds at or after
/// `floor_round` (the last finalized epoch's start): older working
/// state is dead — its rounds are final and their committees never
/// re-open.
pub struct FullSnapshot {
    pub base: FinalitySnapshot,
    pub floor_round: u64,
    pub committees: Vec<(u64, Vec<u64>)>,
    pub draw_base: Vec<(u64, u64)>,
    pub reveals: Vec<(u64, u64, H512)>,
    pub vote_store: Vec<(u64, u64, Vote)>,
    pub voters: Vec<(u64, BlockId, Vec<u64>)>,
    pub canonical_prop: Vec<(u64, u64, BlockId)>,
    pub canonical_vote: Vec<(u64, u64, BlockId)>,
    pub prop_registries: Vec<(u64, Vec<u64>, Vec<Spend>, Vec<(Spend, Spend)>)>,
    pub vote_registries: Vec<(u64, Vec<u64>, Vec<Spend>, Vec<(Spend, Spend)>)>,
    pub owed: Vec<(u64, u64, u64)>,
    pub cast: Vec<(u64, u64, u64)>,
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
        // Insert in causal order, not snapshot order: a block may
        // parent a same-round block, so the snapshot's (round, id)
        // sort can list a child before its parent, and a single pass
        // would silently drop the child — including, fatally, a
        // finalized one. Repeat passes until nothing more fits.
        let mut pending = snap.dag_blocks;
        loop {
            let before = pending.len();
            pending.retain(|b| fin.dag.insert(b.clone()).is_err());
            if pending.is_empty() || pending.len() == before {
                break;
            }
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

    /// Snapshot including the live working state (see
    /// [`FullSnapshot`]). The floor is the last finalized round's
    /// epoch start.
    pub fn snapshot_full(&self) -> FullSnapshot {
        let rpe = self.rounds_per_epoch.max(1);
        let last_final = self.finalized.keys().max().copied().unwrap_or(0);
        let floor = (last_final / rpe) * rpe;
        let reg = |regs: &HashMap<u64, Registry>| -> Vec<(u64, Vec<u64>, Vec<Spend>, Vec<(Spend, Spend)>)> {
            regs.iter()
                .map(|(m, r)| {
                    let pairs: Vec<(u64, Spend)> = r
                        .heights()
                        .iter()
                        .copied()
                        .zip(r.accepted().iter().copied())
                        .filter(|(_, s)| s.nf >= floor)
                        .collect();
                    (
                        *m,
                        pairs.iter().map(|(h, _)| *h).collect(),
                        pairs.iter().map(|(_, s)| *s).collect(),
                        r.evidence()
                            .iter()
                            .copied()
                            .filter(|(a, _)| a.nf >= floor)
                            .collect(),
                    )
                })
                .collect()
        };
        FullSnapshot {
            base: self.snapshot(),
            floor_round: floor,
            committees: self
                .committees
                .iter()
                .filter(|(r, _)| **r >= floor)
                .map(|(r, c)| (*r, c.clone()))
                .collect(),
            draw_base: self
                .draw_base
                .iter()
                .filter(|(r, _)| **r >= floor)
                .map(|(r, n)| (*r, *n))
                .collect(),
            reveals: self
                .reveals
                .iter()
                .filter(|((r, _), _)| *r >= floor)
                .map(|((r, m), l)| (*r, *m, *l))
                .collect(),
            vote_store: self
                .vote_store
                .iter()
                .filter(|((_, r), _)| *r >= floor)
                .map(|((m, r), v)| (*m, *r, v.clone()))
                .collect(),
            voters: self
                .voters
                .iter()
                .filter(|((r, _), _)| *r >= floor)
                .map(|((r, b), s)| (*r, *b, s.iter().copied().collect()))
                .collect(),
            canonical_prop: self
                .canonical_prop
                .iter()
                .filter(|((_, r), _)| *r >= floor)
                .map(|((m, r), b)| (*m, *r, *b))
                .collect(),
            canonical_vote: self
                .canonical_vote
                .iter()
                .filter(|((_, r), _)| *r >= floor)
                .map(|((m, r), b)| (*m, *r, *b))
                .collect(),
            prop_registries: reg(&self.prop_regs),
            vote_registries: reg(&self.vote_regs),
            owed: self
                .owed
                .iter()
                .map(|((m, e), n)| (*m, *e, *n))
                .collect(),
            cast: self
                .cast
                .iter()
                .map(|((m, e), n)| (*m, *e, *n))
                .collect(),
        }
    }

    /// Restore from a full snapshot: the base restore, with the
    /// working state overwritten by the snapshot's.
    pub fn restore_full(snap: FullSnapshot) -> Finality {
        let mut fin = Finality::restore(snap.base);
        for (r, c) in snap.committees {
            fin.committees.insert(r, c);
        }
        for (r, n) in snap.draw_base {
            fin.draw_base.insert(r, n);
        }
        for (r, m, l) in snap.reveals {
            fin.reveals.insert((r, m), l);
        }
        for (m, r, v) in snap.vote_store {
            fin.vote_store.insert((m, r), v);
        }
        for (r, b, s) in snap.voters {
            fin.voters.insert((r, b), s.into_iter().collect());
        }
        for (m, r, b) in snap.canonical_prop {
            fin.canonical_prop.insert((m, r), b);
        }
        for (m, r, b) in snap.canonical_vote {
            fin.canonical_vote.insert((m, r), b);
        }
        for (m, h, a, e) in snap.prop_registries {
            fin.prop_regs.insert(m, Registry::restore(RegistryKind::Proposal, h, a, e));
        }
        for (m, h, a, e) in snap.vote_registries {
            fin.vote_regs.insert(m, Registry::restore(RegistryKind::Vote, h, a, e));
        }
        for (m, e, n) in snap.owed {
            fin.owed.insert((m, e), n);
        }
        for (m, e, n) in snap.cast {
            fin.cast.insert((m, e), n);
        }
        fin
    }

    /// The block this machine canonically proposed for `round`, if
    /// any — a node re-processing a round (catch-up, resume) must
    /// re-serve THIS block, never mint a second one: a second,
    /// different proposal for the same round is equivocation
    /// evidence against itself.
    pub fn canonical_prop_of(&self, machine: u64, round: u64) -> Option<BlockId> {
        self.canonical_prop.get(&(machine, round)).copied()
    }

    /// The blocks this machine has canonically voted for, by round —
    /// used by a resumed node to re-cast votes its restart would
    /// otherwise strand.
    pub fn canonical_votes(&self, machine: u64) -> Vec<(u64, BlockId)> {
        let mut out: Vec<(u64, BlockId)> = self
            .canonical_vote
            .iter()
            .filter(|((m, _), _)| *m == machine)
            .map(|((_, r), b)| (*r, *b))
            .collect();
        out.sort();
        out
    }
}
