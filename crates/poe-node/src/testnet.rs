//! poe-node testnet — the live network node (BUILD_FLOW Step 12c).
//!
//! A long-running node for the public testnet: it holds a persistent
//! identity (an ML-DSA device key, a libp2p transport key, a ticket
//! chain, an XMSS vote key), registers its machine by gossiping a
//! signed announcement, then runs the round loop the manual specifies —
//! reveal, propose, vote, finalize — applying finalized acts to its
//! store and closing epochs through the tokenomics engine.
//!
//! Time is rounds of `round_secs` from the chain's genesis time `t0`,
//! `rounds_per_epoch` rounds to an epoch. Nodes that agree on the spec
//! agree on the round at any wall-clock instant (the partial-synchrony
//! assumption the package itself states).
//!
//! TESTNET ROOT: this chain's attestation root key is PUBLIC — it
//! ships in this crate (`testnet-root-sk.hex`, printed in the repo's
//! testnet/ directory) so anyone can self-attest and join. That is a
//! deliberate testnet property: identities are free, and the falsifier
//! bounties (F-Height, F-Clone, F-First-Year) are about the one law
//! holding anyway. The mainnet roots belong to manufacturers and are
//! never published; nothing about this file carries over to mainnet
//! except the shape.

use crate::genesis::{build_genesis, GenesisSpec, RootSpec};
use poe_crypto::hash::{h, h_u64, Part, H512};
use poe_crypto::pq::DsaKeypair;
use poe_crypto::tickets::TicketChain;
use poe_crypto::xmss::XmssKey;
use poe_dag::{decode_block, encode_block, Block};
use poe_epoch::{EpochEngine, Launch, Profile};
use poe_finality::{
    decode_announcement, decode_vote, encode_announcement, encode_vote, Announcement, Finality,
    MachineInfo, Vote,
};
use poe_identity::{device_id, Attestation, IdentityRegistry};
use poe_kernel::ledger::{Ledger, Note, Op};
use poe_kernel::{Spend, COIN};
use poe_net::{NetNode, TOPIC_ACTS, TOPIC_BLOCKS, TOPIC_VOTES};
use poe_store::encode::{decode_op, encode_ledger, encode_op, Reader};
use poe_store::Store;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const SPEC_TEXT: &str = include_str!("../testnet-1.spec");
const ROOT_SK_HEX: &str = include_str!("../testnet-root-sk.hex");

pub const XMSS_HEIGHT: u32 = 15;
pub const CHAIN_LEN: usize = 20_001;
/// How much finalized history a node retains and re-serves for
/// catching-up peers, in epochs. A bundle sync is only useful while
/// the gap between the bundle's epoch and the frontier fits inside
/// this window, so it is sized in hours, not minutes: 512 epochs at
/// ~48 s is ~6.8 hours — a shipped bundle survives a slow deploy.
/// The cost is memory (the retained window is held anyway by the
/// DAG/finality state at this scale), the benefit is that joining
/// does not require split-second timing.
pub const HISTORY_RETENTION_EPOCHS: u64 = 512;

// -- hex ---------------------------------------------------------------------

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let hi = char::from(b[i]).to_digit(16)?;
        let lo = char::from(b[i + 1]).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

// -- chain spec ---------------------------------------------------------------

pub struct Spec {
    pub name: String,
    pub root_id: u64,
    pub root_quota: u64,
    pub root_pk: Vec<u8>,
    pub rounds_per_epoch: u64,
    pub round_secs: u64,
    pub ghostdag_k: u64,
    pub t0_unix: u64,
    pub genesis_hash: H512,
}

impl Spec {
    pub fn parse(text: &str) -> io::Result<Spec> {
        let mut kv: HashMap<String, String> = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                kv.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
        let get = |k: &str| -> io::Result<String> {
            kv.get(k)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("spec missing {k}")))
        };
        let num = |k: &str| -> io::Result<u64> {
            get(k)?
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("spec {k} not a number")))
        };
        let root_pk = hex_decode(&get("root_pk")?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "spec root_pk not hex"))?;
        let gh = hex_decode(&get("genesis_hash")?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "spec genesis_hash not hex"))?;
        Ok(Spec {
            name: get("name")?,
            root_id: num("root_id")?,
            root_quota: num("root_quota")?,
            root_pk,
            rounds_per_epoch: num("rounds_per_epoch")?,
            round_secs: num("round_secs")?,
            ghostdag_k: num("ghostdag_k")?,
            t0_unix: num("t0_unix")?,
            genesis_hash: gh
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "genesis_hash must be 64 bytes"))?,
        })
    }

    pub fn genesis_spec(&self) -> GenesisSpec {
        GenesisSpec {
            profile: Profile::REFERENCE,
            launch: Launch::FairV1,
            roots: vec![RootSpec {
                root_id: self.root_id,
                root_pk: self.root_pk.clone(),
                quota_per_epoch: self.root_quota,
            }],
        }
    }

    fn round_at(&self, unix: u64) -> u64 {
        unix.saturating_sub(self.t0_unix) / self.round_secs.max(1)
    }

    fn round_start_unix(&self, round: u64) -> u64 {
        self.t0_unix + round * self.round_secs
    }
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// -- node identity ------------------------------------------------------------

struct Keys {
    device: DsaKeypair,
    machine: u64,
    chain: TicketChain,
    xmss: XmssKey,
    xmss_path: PathBuf,
}

fn load_or_create_keys(dir: &Path, rng: &mut rand::rngs::ThreadRng) -> io::Result<Keys> {
    std::fs::create_dir_all(dir)?;
    let dev_path = dir.join("device.key");
    let device = if dev_path.exists() {
        let text = std::fs::read_to_string(&dev_path)?;
        let mut lines = text.lines();
        let pk = hex_decode(lines.next().unwrap_or(""))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "device.key pk"))?;
        let sk = hex_decode(lines.next().unwrap_or(""))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "device.key sk"))?;
        DsaKeypair::from_key_bytes(&pk, &sk)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "device.key does not parse"))?
    } else {
        let kp = DsaKeypair::generate(rng);
        std::fs::write(
            &dev_path,
            format!("{}\n{}\n", hex_encode(&kp.public_key_bytes()), hex_encode(&kp.secret_key_bytes())),
        )?;
        kp
    };
    let machine = device_id(&device.public_key_bytes());

    let chain_path = dir.join("ticket.seed");
    let chain = if chain_path.exists() {
        let seed = std::fs::read(&chain_path)?;
        TicketChain::new(&seed, CHAIN_LEN)
    } else {
        let mut seed = vec![0u8; 32];
        use rand::RngCore;
        rng.fill_bytes(&mut seed);
        std::fs::write(&chain_path, &seed)?;
        TicketChain::new(&seed, CHAIN_LEN)
    };

    let xmss_path = dir.join("xmss.key");
    let xmss = if xmss_path.exists() {
        XmssKey::load(&xmss_path).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("xmss load: {e:?}")))?
    } else {
        let mut seed = [0u8; 32];
        use rand::RngCore;
        rng.fill_bytes(&mut seed);
        let key = XmssKey::generate(seed, XMSS_HEIGHT);
        key.save(&xmss_path).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("xmss save: {e:?}")))?;
        key
    };
    Ok(Keys { device, machine, chain, xmss, xmss_path })
}

fn load_or_create_peer_key(dir: &Path) -> io::Result<libp2p::identity::Keypair> {
    let path = dir.join("peer.key");
    if path.exists() {
        let bytes = std::fs::read(&path)?;
        libp2p::identity::Keypair::from_protobuf_encoding(&bytes).map_err(io::Error::other)
    } else {
        let kp = libp2p::identity::Keypair::generate_ed25519();
        std::fs::write(&path, kp.to_protobuf_encoding().map_err(io::Error::other)?)?;
        Ok(kp)
    }
}

// -- payloads -----------------------------------------------------------------

fn ops_payload(ops: &[Op]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(ops.len() as u32).to_be_bytes());
    for op in ops {
        let b = encode_op(op);
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(&b);
    }
    out
}

fn decode_ops(payload: &[u8]) -> Vec<Op> {
    let mut ops = Vec::new();
    if payload.len() < 4 {
        return ops;
    }
    let n = u32::from_be_bytes(payload[0..4].try_into().expect("4")) as usize;
    let mut off = 4usize;
    for _ in 0..n.min(4096) {
        if off + 4 > payload.len() {
            break;
        }
        let len = u32::from_be_bytes(payload[off..off + 4].try_into().expect("4")) as usize;
        off += 4;
        if off + len > payload.len() {
            break;
        }
        let mut r = Reader::new(&payload[off..off + len]);
        if let Some(op) = decode_op(&mut r) {
            ops.push(op);
        }
        off += len;
    }
    ops
}

/// Gossip framing: tag (1 byte) + nonce (8 bytes) + body. See
/// handle_inbound for why the nonce exists (gossipsub dedup).
fn framed(tag: u8, nonce: u64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + body.len());
    out.push(tag);
    out.extend_from_slice(&nonce.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn reveal_msg(machine: u64, round: u64, link: &H512, nonce: u64) -> Vec<u8> {
    let mut body = Vec::with_capacity(80);
    body.extend_from_slice(&machine.to_be_bytes());
    body.extend_from_slice(&round.to_be_bytes());
    body.extend_from_slice(link);
    framed(1, nonce, &body)
}

fn heartbeat_msg(machine: u64, epoch: u64, sig: &[u8], nonce: u64) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&machine.to_be_bytes());
    body.extend_from_slice(&epoch.to_be_bytes());
    body.extend_from_slice(&(sig.len() as u32).to_be_bytes());
    body.extend_from_slice(sig);
    framed(4, nonce, &body)
}

// -- sync bundle (one file: store snapshot + finality snapshot + meta) -------

const BUNDLE_MAGIC: &[u8; 8] = b"POEBNDL1";

fn w_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn w_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn w_bytes(out: &mut Vec<u8>, b: &[u8]) {
    w_u64(out, b.len() as u64);
    out.extend_from_slice(b);
}

struct Cursor<'a> {
    raw: &'a [u8],
    off: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self
            .off
            .checked_add(n)
            .filter(|e| *e <= self.raw.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "bundle truncated"))?;
        let s = &self.raw[self.off..end];
        self.off = end;
        Ok(s)
    }
    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4")))
    }
    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("8")))
    }
    fn bytes(&mut self) -> io::Result<Vec<u8>> {
        let n = self.u64()? as usize;
        Ok(self.take(n)?.to_vec())
    }
}

pub struct Bundle {
    pub sync_epoch: u64,
    pub sync_round: u64,
    pub store_files: Vec<(String, Vec<u8>)>,
    pub fin: poe_finality::FinalitySnapshot,
    pub announcements: Vec<Announcement>,
}

fn write_bundle(
    path: &Path,
    store_dir: &Path,
    fin: &Finality,
    announcements: &BTreeMap<u64, Announcement>,
    sync_epoch: u64,
    sync_round: u64,
) -> io::Result<()> {
    let mut out = Vec::new();
    out.extend_from_slice(BUNDLE_MAGIC);
    w_u64(&mut out, sync_epoch);
    w_u64(&mut out, sync_round);
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    for name in ["ledger.snapshot", "ops.log"] {
        let p = store_dir.join(name);
        if p.exists() {
            files.push((name.to_string(), std::fs::read(&p)?));
        }
    }
    w_u32(&mut out, files.len() as u32);
    for (name, bytes) in &files {
        w_bytes(&mut out, name.as_bytes());
        w_bytes(&mut out, bytes);
    }
    let snap = fin.snapshot();
    w_u64(&mut out, snap.k);
    w_u64(&mut out, snap.rounds_per_epoch);
    w_u32(&mut out, snap.dag_blocks.len() as u32);
    for b in &snap.dag_blocks {
        w_bytes(&mut out, &encode_block(b));
    }
    w_u32(&mut out, snap.machines.len() as u32);
    for (id, info) in &snap.machines {
        w_u64(&mut out, *id);
        out.extend_from_slice(&info.xmss_root);
        out.extend_from_slice(&info.xmss_height.to_be_bytes());
        out.extend_from_slice(&info.chain_commitment);
        w_bytes(&mut out, &info.dsa_public_key);
    }
    w_u32(&mut out, snap.revoked.len() as u32);
    for (m, e) in &snap.revoked {
        w_u64(&mut out, *m);
        w_u64(&mut out, *e);
    }
    w_u32(&mut out, snap.used_leaves.len() as u32);
    for (m, leaves) in &snap.used_leaves {
        w_u64(&mut out, *m);
        w_u32(&mut out, leaves.len() as u32);
        for l in leaves {
            w_u64(&mut out, *l);
        }
    }
    w_u32(&mut out, snap.finalized.len() as u32);
    for (r, b) in &snap.finalized {
        w_u64(&mut out, *r);
        out.extend_from_slice(b);
    }
    w_u32(&mut out, announcements.len() as u32);
    for a in announcements.values() {
        w_bytes(&mut out, &encode_announcement(a));
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &out)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn read_bundle(path: &Path) -> io::Result<Bundle> {
    let raw = std::fs::read(path)?;
    let mut c = Cursor { raw: &raw, off: 0 };
    if c.take(8)? != BUNDLE_MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a poe bundle"));
    }
    let sync_epoch = c.u64()?;
    let sync_round = c.u64()?;
    let nf = c.u32()?;
    let mut store_files = Vec::new();
    for _ in 0..nf {
        let name = String::from_utf8(c.bytes()?)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bundle file name"))?;
        let bytes = c.bytes()?;
        store_files.push((name, bytes));
    }
    let k = c.u64()?;
    let rpe = c.u64()?;
    let nb = c.u32()?;
    let mut dag_blocks = Vec::new();
    for _ in 0..nb {
        let b = c.bytes()?;
        dag_blocks.push(
            decode_block(&b)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bundle block"))?,
        );
    }
    let nm = c.u32()?;
    let mut machines = Vec::new();
    for _ in 0..nm {
        let id = c.u64()?;
        let xmss_root: [u8; 32] = c.take(32)?.try_into().expect("32");
        let xmss_height = u32::from_be_bytes(c.take(4)?.try_into().expect("4"));
        let chain_commitment: H512 = c.take(64)?.try_into().expect("64");
        let dsa_public_key = c.bytes()?;
        machines.push((id, MachineInfo { xmss_root, xmss_height, chain_commitment, dsa_public_key }));
    }
    let nr = c.u32()?;
    let mut revoked = Vec::new();
    for _ in 0..nr {
        revoked.push((c.u64()?, c.u64()?));
    }
    let nu = c.u32()?;
    let mut used_leaves = Vec::new();
    for _ in 0..nu {
        let m = c.u64()?;
        let n = c.u32()?;
        let mut leaves = Vec::new();
        for _ in 0..n {
            leaves.push(c.u64()?);
        }
        used_leaves.push((m, leaves));
    }
    let nfin = c.u32()?;
    let mut finalized = Vec::new();
    for _ in 0..nfin {
        let r = c.u64()?;
        let b: H512 = c.take(64)?.try_into().expect("64");
        finalized.push((r, b));
    }
    let na = c.u32()?;
    let mut announcements = Vec::new();
    for _ in 0..na {
        let b = c.bytes()?;
        announcements.push(
            decode_announcement(&b)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bundle announcement"))?,
        );
    }
    Ok(Bundle {
        sync_epoch,
        sync_round,
        store_files,
        fin: poe_finality::FinalitySnapshot {
            k,
            rounds_per_epoch: rpe,
            machines,
            revoked,
            used_leaves,
            finalized,
            dag_blocks,
        },
        announcements,
    })
}

// -- per-round local state (restart resume) -----------------------------------
//
// The bundle is written at epoch closes and rewinds the store with
// it. A node's own restart needs finer grain: the finstate file is
// written at the end of EVERY round and carries the full finality
// working state plus how far the ledger has applied, so a restarted
// node resumes exactly where it stopped — its own store is never
// rewound, and the votes it cast in its last rounds survive in its
// vote store (and can be re-cast; see run_testnet).

const FINSTATE_MAGIC: &[u8; 8] = b"POEFIN1\0";

fn w_spend(out: &mut Vec<u8>, s: &Spend) {
    w_u64(out, s.tx);
    w_u64(out, s.nf);
}

fn write_finstate(path: &Path, fin: &Finality, next_apply: u64) -> io::Result<()> {
    let snap = fin.snapshot_full();
    let base = &snap.base;
    let mut out = Vec::new();
    out.extend_from_slice(FINSTATE_MAGIC);
    w_u64(&mut out, next_apply);
    w_u64(&mut out, snap.floor_round);
    w_u64(&mut out, base.k);
    w_u64(&mut out, base.rounds_per_epoch);
    w_u32(&mut out, base.dag_blocks.len() as u32);
    for b in &base.dag_blocks {
        w_bytes(&mut out, &encode_block(b));
    }
    w_u32(&mut out, base.machines.len() as u32);
    for (id, info) in &base.machines {
        w_u64(&mut out, *id);
        out.extend_from_slice(&info.xmss_root);
        out.extend_from_slice(&info.xmss_height.to_be_bytes());
        out.extend_from_slice(&info.chain_commitment);
        w_bytes(&mut out, &info.dsa_public_key);
    }
    w_u32(&mut out, base.revoked.len() as u32);
    for (m, e) in &base.revoked {
        w_u64(&mut out, *m);
        w_u64(&mut out, *e);
    }
    w_u32(&mut out, base.used_leaves.len() as u32);
    for (m, leaves) in &base.used_leaves {
        w_u64(&mut out, *m);
        w_u32(&mut out, leaves.len() as u32);
        for l in leaves {
            w_u64(&mut out, *l);
        }
    }
    w_u32(&mut out, base.finalized.len() as u32);
    for (r, b) in &base.finalized {
        w_u64(&mut out, *r);
        out.extend_from_slice(b);
    }
    w_u32(&mut out, snap.committees.len() as u32);
    for (r, members) in &snap.committees {
        w_u64(&mut out, *r);
        w_u32(&mut out, members.len() as u32);
        for m in members {
            w_u64(&mut out, *m);
        }
    }
    w_u32(&mut out, snap.reveals.len() as u32);
    for (r, m, l) in &snap.reveals {
        w_u64(&mut out, *r);
        w_u64(&mut out, *m);
        out.extend_from_slice(l);
    }
    w_u32(&mut out, snap.vote_store.len() as u32);
    for (_, _, v) in &snap.vote_store {
        w_bytes(&mut out, &encode_vote(v));
    }
    w_u32(&mut out, snap.voters.len() as u32);
    for (r, b, vs) in &snap.voters {
        w_u64(&mut out, *r);
        out.extend_from_slice(b);
        w_u32(&mut out, vs.len() as u32);
        for m in vs {
            w_u64(&mut out, *m);
        }
    }
    for canon in [&snap.canonical_prop, &snap.canonical_vote] {
        w_u32(&mut out, canon.len() as u32);
        for (m, r, b) in canon {
            w_u64(&mut out, *m);
            w_u64(&mut out, *r);
            out.extend_from_slice(b);
        }
    }
    for regs in [&snap.prop_registries, &snap.vote_registries] {
        w_u32(&mut out, regs.len() as u32);
        for (m, heights, accepted, evidence) in regs {
            w_u64(&mut out, *m);
            w_u32(&mut out, heights.len() as u32);
            for h in heights {
                w_u64(&mut out, *h);
            }
            w_u32(&mut out, accepted.len() as u32);
            for s in accepted {
                w_spend(&mut out, s);
            }
            w_u32(&mut out, evidence.len() as u32);
            for (a, b) in evidence {
                w_spend(&mut out, a);
                w_spend(&mut out, b);
            }
        }
    }
    for counters in [&snap.owed, &snap.cast] {
        w_u32(&mut out, counters.len() as u32);
        for (m, e, n) in counters {
            w_u64(&mut out, *m);
            w_u64(&mut out, *e);
            w_u64(&mut out, *n);
        }
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        std::io::Write::write_all(&mut f, &out)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn read_finstate(path: &Path) -> io::Result<(Finality, u64)> {
    let raw = std::fs::read(path)?;
    let mut c = Cursor { raw: &raw, off: 0 };
    if c.take(8)? != FINSTATE_MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a poe finstate"));
    }
    let next_apply = c.u64()?;
    let floor_round = c.u64()?;
    let k = c.u64()?;
    let rpe = c.u64()?;
    let nb = c.u32()?;
    let mut dag_blocks = Vec::new();
    for _ in 0..nb {
        let b = c.bytes()?;
        dag_blocks.push(
            decode_block(&b)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "finstate block"))?,
        );
    }
    let nm = c.u32()?;
    let mut machines = Vec::new();
    for _ in 0..nm {
        let id = c.u64()?;
        let xmss_root: [u8; 32] = c.take(32)?.try_into().expect("32");
        let xmss_height = u32::from_be_bytes(c.take(4)?.try_into().expect("4"));
        let chain_commitment: H512 = c.take(64)?.try_into().expect("64");
        let dsa_public_key = c.bytes()?;
        machines.push((id, MachineInfo { xmss_root, xmss_height, chain_commitment, dsa_public_key }));
    }
    let nr = c.u32()?;
    let mut revoked = Vec::new();
    for _ in 0..nr {
        revoked.push((c.u64()?, c.u64()?));
    }
    let nu = c.u32()?;
    let mut used_leaves = Vec::new();
    for _ in 0..nu {
        let m = c.u64()?;
        let n = c.u32()?;
        let mut leaves = Vec::new();
        for _ in 0..n {
            leaves.push(c.u64()?);
        }
        used_leaves.push((m, leaves));
    }
    let nfin = c.u32()?;
    let mut finalized = Vec::new();
    for _ in 0..nfin {
        let r = c.u64()?;
        let b: H512 = c.take(64)?.try_into().expect("64");
        finalized.push((r, b));
    }
    let nc = c.u32()?;
    let mut committees = Vec::new();
    for _ in 0..nc {
        let r = c.u64()?;
        let n = c.u32()?;
        let mut members = Vec::new();
        for _ in 0..n {
            members.push(c.u64()?);
        }
        committees.push((r, members));
    }
    let nrv = c.u32()?;
    let mut reveals = Vec::new();
    for _ in 0..nrv {
        let r = c.u64()?;
        let m = c.u64()?;
        let l: H512 = c.take(64)?.try_into().expect("64");
        reveals.push((r, m, l));
    }
    let nvs = c.u32()?;
    let mut vote_store = Vec::new();
    for _ in 0..nvs {
        let b = c.bytes()?;
        let v = decode_vote(&b)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "finstate vote"))?;
        vote_store.push((v.machine, v.round, v));
    }
    let nvt = c.u32()?;
    let mut voters = Vec::new();
    for _ in 0..nvt {
        let r = c.u64()?;
        let b: H512 = c.take(64)?.try_into().expect("64");
        let n = c.u32()?;
        let mut vs = Vec::new();
        for _ in 0..n {
            vs.push(c.u64()?);
        }
        voters.push((r, b, vs));
    }
    let mut canons = Vec::new();
    for _ in 0..2 {
        let n = c.u32()?;
        let mut entries = Vec::new();
        for _ in 0..n {
            let m = c.u64()?;
            let r = c.u64()?;
            let b: H512 = c.take(64)?.try_into().expect("64");
            entries.push((m, r, b));
        }
        canons.push(entries);
    }
    let mut all_regs = Vec::new();
    for _ in 0..2 {
        let n = c.u32()?;
        let mut regs = Vec::new();
        for _ in 0..n {
            let m = c.u64()?;
            let nh = c.u32()?;
            let mut heights = Vec::new();
            for _ in 0..nh {
                heights.push(c.u64()?);
            }
            let na = c.u32()?;
            let mut accepted = Vec::new();
            for _ in 0..na {
                accepted.push(Spend { tx: c.u64()?, nf: c.u64()? });
            }
            let ne = c.u32()?;
            let mut evidence = Vec::new();
            for _ in 0..ne {
                let a = Spend { tx: c.u64()?, nf: c.u64()? };
                let b = Spend { tx: c.u64()?, nf: c.u64()? };
                evidence.push((a, b));
            }
            regs.push((m, heights, accepted, evidence));
        }
        all_regs.push(regs);
    }
    let mut counters_all = Vec::new();
    for _ in 0..2 {
        let n = c.u32()?;
        let mut entries = Vec::new();
        for _ in 0..n {
            entries.push((c.u64()?, c.u64()?, c.u64()?));
        }
        counters_all.push(entries);
    }
    let mut canons = canons.into_iter();
    let mut all_regs = all_regs.into_iter();
    let mut counters_all = counters_all.into_iter();
    let full = poe_finality::FullSnapshot {
        base: poe_finality::FinalitySnapshot {
            k,
            rounds_per_epoch: rpe,
            machines,
            revoked,
            used_leaves,
            finalized,
            dag_blocks,
        },
        floor_round,
        committees,
        reveals,
        vote_store,
        voters,
        canonical_prop: canons.next().unwrap_or_default(),
        canonical_vote: canons.next().unwrap_or_default(),
        prop_registries: all_regs.next().unwrap_or_default(),
        vote_registries: all_regs.next().unwrap_or_default(),
        owed: counters_all.next().unwrap_or_default(),
        cast: counters_all.next().unwrap_or_default(),
    };
    Ok((Finality::restore_full(full), next_apply))
}

// -- the node -----------------------------------------------------------------

pub struct TestnetArgs {
    pub dir: PathBuf,
    pub listen: String,
    pub peers: Vec<String>,
    pub sync_from: Option<PathBuf>,
    pub run_rounds: u64,
}

struct Node {
    spec: Spec,
    engine: EpochEngine,
    identity: IdentityRegistry,
    store: Store,
    fin: Finality,
    net: NetNode,
    /// Configured peers, re-dialed periodically: a dial fired while
    /// the peer is still deriving its keys (or down) is lost, and a
    /// node that never connects silently runs a solo chain.
    peer_addrs: Vec<libp2p::Multiaddr>,
    keys: Keys,
    my_announcement: Announcement,
    announcements: BTreeMap<u64, Announcement>,
    pending_ann: Vec<Announcement>,
    buffered_blocks: Vec<Block>,
    buffered_votes: Vec<Vote>,
    /// Reveals received over gossip, held until their machine is
    /// registered here. A reveal that arrives before its announcement
    /// is registered (always the case during the pre-genesis wait,
    /// when registrations have not landed yet) must not be dropped:
    /// losing one shrinks this node's committee for that round to the
    /// machines whose reveals survived, and committees of different
    /// sizes finalize different blocks.
    pending_reveals: HashMap<(u64, u64), H512>,
    /// While the current round is below this, the node re-serves the
    /// current epoch's history (blocks, reveals, accepted votes) every
    /// round: a peer that synced from an epoch-boundary bundle needs
    /// exactly that history to finalize the rounds since the bundle,
    /// and plain gossip has no memory. Set at startup and extended
    /// whenever a new machine registers.
    history_until: u64,
    /// The oldest sync point announced by a recently registered
    /// machine (from its announcement's sync hint). History
    /// re-service reaches back to this round's epoch — the joiner's
    /// clock, not the publisher's.
    catchup_from: Option<u64>,
    heartbeats: HashMap<(u64, u64), Vec<u8>>,
    hb_signed: HashSet<u64>,
    next_apply: u64,
    last_closed: Option<u64>,
    join_inflight: Option<u64>,
    genesis_id: H512,
    /// The round whose reveals are currently being collected (reveals
    /// lead by one round: round r's committee is sampled from links
    /// revealed during round r-1).
    collect_round: u64,
    /// A freshly synced node only observes through this round: it
    /// missed the reveal collection for it, so it must not act in it.
    observe_until: Option<u64>,
    voted: HashSet<u64>,
    /// True when this node synced from an epoch bundle (not a plain
    /// start, not a full local resume). Such a node rebuilds its
    /// committees for the catch-up rounds from re-served history and
    /// must give that history time to arrive before closing them —
    /// see the catch-up dwell in process_round.
    bundle_synced: bool,
    /// Next round of the history range to re-serve (see the serve
    /// block in process_round): serving the whole range every round
    /// floods the mesh and the publisher; the range is walked in
    /// slices instead.
    serve_cursor: u64,
}

fn attestation_of(a: &Announcement) -> Attestation {
    Attestation {
        device_pk: a.device_pk.clone(),
        root_id: a.root_id,
        serial: a.serial,
        expiry_epoch: a.expiry_epoch,
        signature: a.root_signature.clone(),
    }
}

impl Node {
    /// Propose a gossiped block without ever letting the DAG layer's
    /// strictness kill the node: a block whose parents are not all in
    /// my DAG yet (out-of-order or gapped delivery) is buffered for a
    /// later round, as is one whose author's reveal or registration
    /// has not reached me. Anything else is final — accepted, duplicate,
    /// evidence, or refused.
    fn propose_guarded(&mut self, b: Block) -> bool {
        if b.parents.is_empty() && b.id != self.genesis_id {
            return true; // a foreign genesis: never buffer, never insert
        }
        if !b.parents.iter().all(|p| self.fin.dag.get(p).is_some()) {
            return false;
        }
        match self.fin.propose(b.clone()) {
            Ok(_) => true,
            Err(poe_finality::FinError::BadReveal)
            | Err(poe_finality::FinError::UnknownMachine) => false,
            // A NotProposer verdict is only trustworthy once my beacon
            // for that round is settled — i.e. once the round two back
            // is final here. Before that, my reference block may lag the
            // proposer's, so buffer and retry instead of dropping a
            // block every caught-up node accepts.
            Err(poe_finality::FinError::NotProposer)
                if b.round >= 2 && !self.fin.finalized.contains_key(&(b.round - 2)) =>
            {
                false
            }
            Err(_) => true,
        }
    }

    fn register_announcement(&mut self, a: &Announcement, epoch: u64) -> bool {
        let machine = device_id(&a.device_pk);
        if self.announcements.contains_key(&machine) {
            return false;
        }
        let att = attestation_of(a);
        if self.identity.bind(&att, machine, epoch).is_err() {
            return false;
        }
        self.fin.register_machine(
            machine,
            MachineInfo {
                xmss_root: a.xmss_root,
                xmss_height: a.xmss_height,
                chain_commitment: a.chain_commitment,
                dsa_public_key: a.device_pk.clone(),
            },
        );
        self.announcements.insert(machine, a.clone());
        true
    }

    /// Submit every buffered reveal whose machine is now registered.
    /// Reveals for already-closed rounds are harmless to submit late
    /// (the sampling already happened); the point is that a reveal is
    /// never LOST, so by the time a round's committee is sampled, every
    /// honest node's reveal set is complete.
    fn flush_reveals(&mut self) {
        let keys: Vec<(u64, u64)> = self.pending_reveals.keys().copied().collect();
        for k in keys {
            let link = self.pending_reveals[&k];
            match self.fin.submit_reveal(k.0, k.1, link) {
                Ok(()) => {
                    self.pending_reveals.remove(&k);
                }
                Err(poe_finality::FinError::UnknownMachine) => {} // keep; registration may land later
                Err(_) => {
                    self.pending_reveals.remove(&k); // invalid or revoked: garbage, drop
                }
            }
        }
    }

    fn handle_inbound(&mut self, inb: poe_net::Inbound) {
        // Gossip framing: tag (1 byte) + nonce (8 bytes) + body. The
        // nonce makes every republication a fresh gossip message —
        // gossipsub deduplicates by content hash, so re-sending
        // identical bytes is silently suppressed, which is how the
        // first (pre-mesh) publication of a reveal or announcement
        // used to be lost for good.
        if inb.data.len() < 9 {
            return;
        }
        let body = &inb.data[9..];
        match (inb.topic.as_str(), inb.data[0]) {
            (TOPIC_BLOCKS, 1) if body.len() == 80 => {
                let machine = u64::from_be_bytes(body[0..8].try_into().expect("8"));
                let round = u64::from_be_bytes(body[8..16].try_into().expect("8"));
                let link: H512 = body[16..80].try_into().expect("64");
                // Buffer, don't submit: the machine may not be
                // registered here yet, and submit_reveal would refuse
                // (and the reveal would be gone). flush_reveals()
                // submits it once registration has landed.
                self.pending_reveals.insert((machine, round), link);
            }
            (TOPIC_BLOCKS, 2) => {
                if let Some(b) = decode_block(body) {
                    if !self.propose_guarded(b.clone()) {
                        self.buffered_blocks.push(b);
                    }
                }
            }
            (TOPIC_VOTES, 3) => {
                if let Some(v) = decode_vote(body) {
                    self.buffered_votes.push(v);
                }
            }
            (TOPIC_VOTES, 4) if body.len() >= 20 => {
                let machine = u64::from_be_bytes(body[0..8].try_into().expect("8"));
                let epoch = u64::from_be_bytes(body[8..16].try_into().expect("8"));
                let len = u32::from_be_bytes(body[16..20].try_into().expect("4")) as usize;
                if body.len() == 20 + len {
                    self.heartbeats.insert((machine, epoch), body[20..].to_vec());
                }
            }
            (TOPIC_ACTS, 5) => {
                if let Some(a) = decode_announcement(body) {
                    let machine = device_id(&a.device_pk);
                    if !self.announcements.contains_key(&machine) {
                        self.pending_ann.push(a);
                    }
                }
            }
            _ => {}
        }
    }

    fn drain_votes(&mut self) {
        let pending = std::mem::take(&mut self.buffered_votes);
        for v in pending {
            match self.fin.vote(v.clone()) {
                Ok(_) => {}
                Err(poe_finality::FinError::RoundNotClosed)
                | Err(poe_finality::FinError::UnknownBlock) => {
                    self.buffered_votes.push(v);
                }
                Err(_) => {}
            }
        }
    }

    fn apply_finalized(&mut self) -> io::Result<()> {
        while let Some(bid) = self.fin.finalized.get(&self.next_apply).copied() {
            // A finalized block not yet in the local DAG is a wait,
            // not a death: it can still arrive (or be re-served), and
            // the next round retries. Killing the node here turned a
            // recoverable sync gap into a permanent exit.
            let Some(block) = self.fin.dag.get(&bid).cloned() else {
                return Ok(());
            };
            for op in decode_ops(&block.payload) {
                let _ = self.engine.apply(self.store.ledger(), &op);
                self.store.apply(&op)?;
            }
            self.next_apply += 1;
        }
        Ok(())
    }

    fn try_close(&mut self, epoch: u64, dir: &Path) -> io::Result<bool> {
        let rpe = self.spec.rounds_per_epoch;
        if self.last_closed == Some(epoch) || self.store.ledger().now != epoch {
            return Ok(false);
        }
        if self.next_apply < (epoch + 1) * rpe {
            return Ok(false); // the epoch's rounds are not all applied yet
        }
        let mut credited: Vec<u64> = Vec::new();
        let machines: Vec<u64> = self.announcements.keys().copied().collect();
        for m in machines {
            let sig_ok = match self.heartbeats.get(&(m, epoch)) {
                Some(sig) => self.fin.verify_heartbeat(m, epoch, sig).is_ok(),
                None => false,
            };
            if sig_ok && self.fin.heartbeat_credited(m, epoch) {
                credited.push(m);
            }
        }
        let mut l2: Ledger = self.store.ledger().clone();
        let rep = self.engine.close(&mut l2, 1000, &credited);
        self.store.apply(&Op::Tick { cap: rep.cap_handed })?;
        if encode_ledger(self.store.ledger()) != encode_ledger(&l2) {
            println!("DIVERGENCE epoch={epoch}: engine and store disagree after the close");
        }
        self.store.snapshot()?;
        // Roots are keyed by the epoch being entered: the root after
        // epoch `epoch`'s close is state_root_at(epoch + 1).
        let root = self
            .store
            .state_root_at(epoch + 1)
            .map(|r| hex_encode(&r[..8]))
            .unwrap_or_else(|| "none".to_string());
        println!(
            "CLOSE epoch={epoch} claimants={} grant_each={} minted_total={} credited={} root={}",
            rep.claimants,
            rep.grant_each,
            self.store.ledger().minted,
            credited.len(),
            root
        );
        let bundle_path = dir.join("bundle.bin");
        write_bundle(
            &bundle_path,
            &dir.join("store"),
            &self.fin,
            &self.announcements,
            epoch,
            (epoch + 1) * rpe,
        )?;
        self.last_closed = Some(epoch);
        Ok(true)
    }
}

/// Generate a fresh testnet root keypair into `dir` (root-pk.hex,
/// root-sk.hex). Used once, at chain launch, by the operator; for this
/// testnet the secret is then published on purpose (see the module doc).
pub fn root_keygen(dir: &Path) -> io::Result<String> {
    std::fs::create_dir_all(dir)?;
    let mut rng = rand::thread_rng();
    let kp = DsaKeypair::generate(&mut rng);
    std::fs::write(dir.join("root-pk.hex"), hex_encode(&kp.public_key_bytes()))?;
    std::fs::write(dir.join("root-sk.hex"), hex_encode(&kp.secret_key_bytes()))?;
    Ok(hex_encode(&kp.public_key_bytes()))
}

pub async fn run_testnet(args: TestnetArgs) -> io::Result<()> {
    let spec = Spec::parse(SPEC_TEXT)?;
    // The late-start check runs at PROCESS start, before key loading:
    // deriving the XMSS vote key takes minutes on this class of
    // machine, and a node launched before genesis whose keys finish
    // deriving after it is a genesis participant catching up (the
    // sequential round loop replays the missed rounds), not a late
    // joiner. A process actually STARTED after genesis with an empty
    // data dir is still refused: it must sync from a bundle.
    let store_dir_pre = args.dir.join("store");
    let store_existed = store_dir_pre.join("ledger.snapshot").exists()
        || std::fs::metadata(store_dir_pre.join("ops.log")).map(|m| m.len() > 0).unwrap_or(false);
    if args.sync_from.is_none() && !store_existed && spec.round_at(now_unix()) > 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "this chain has already started and the data dir is empty — start with --sync-from <bundle.bin> from a running node",
        ));
    }
    // Restart resume: a node whose data dir holds its own bundle from
    // a previous run restores from it, exactly like an external sync —
    // ledger and finality rewind to its last epoch close, and the
    // epoch-history gossip (see process_round) replays the rounds
    // since. Without this, a restarted node could never rejoin its
    // own chain.
    let own_bundle = args.dir.join("bundle.bin");
    let self_resume = args.sync_from.is_none() && store_existed && own_bundle.exists();
    // Finer-grained resume: the per-round finstate (see write_finstate)
    // takes precedence over the epoch bundle when both exist — the
    // store is not rewound at all on this path.
    let finstate_path = args.dir.join("finstate.bin");
    let full_resume = args.sync_from.is_none() && store_existed && finstate_path.exists();
    let sync_path: Option<PathBuf> = match &args.sync_from {
        Some(p) => Some(p.clone()),
        None if self_resume => Some(own_bundle.clone()),
        None => None,
    };
    let bundle0 = build_genesis(&spec.genesis_spec());
    if bundle0.hash != spec.genesis_hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "spec genesis hash mismatch — this binary's frozen spec is not the chain's",
        ));
    }
    let mut rng = rand::thread_rng();
    let dir = args.dir.clone();
    std::fs::create_dir_all(&dir)?;
    let keys = load_or_create_keys(&dir, &mut rng)?;
    let machine = keys.machine;

    // Self-attestation under the (public) testnet root.
    let root_sk = hex_decode(ROOT_SK_HEX)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "embedded root key"))?;
    let root = DsaKeypair::from_key_bytes(&spec.root_pk, &root_sk)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "root keypair does not rebuild"))?;
    let att = Attestation::issue(
        &root,
        &mut rng,
        keys.device.public_key_bytes(),
        spec.root_id,
        machine,
        1_000_000,
    );
    let mut my_announcement = Announcement {
        device_pk: att.device_pk.clone(),
        root_id: att.root_id,
        serial: att.serial,
        expiry_epoch: att.expiry_epoch,
        root_signature: att.signature.clone(),
        xmss_root: keys.xmss.root(),
        xmss_height: XMSS_HEIGHT,
        chain_commitment: keys.chain.commitment(),
        sync_hint: 0,
    };

    // Store + finality: fresh, or restored from a sync bundle.
    let store_dir = dir.join("store");
    let (mut fin, mut next_apply, sync_note) = if full_resume {
        let (fin, na) = read_finstate(&finstate_path)?;
        (fin, na, format!("resumed from local state at round {na}"))
    } else if let Some(bundle_path) = &sync_path {
        if args.sync_from.is_some() && store_existed {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "--sync-from given but this data dir already has a store",
            ));
        }
        let bundle = read_bundle(bundle_path)?;
        std::fs::create_dir_all(&store_dir)?;
        for (name, bytes) in &bundle.store_files {
            std::fs::write(store_dir.join(name), bytes)?;
        }
        let fin = Finality::restore(bundle.fin);
        let note = format!(
            "synced from bundle at epoch {} (round {})",
            bundle.sync_epoch, bundle.sync_round
        );
        let anns = bundle.announcements.clone();
        let mut node_fin = fin;
        // Announcements ride along so registrations can be rebuilt in the
        // identity registry below (finality already has the machines).
        pending_bundle_announcements(anns);
        let _ = &mut node_fin;
        (node_fin, bundle.sync_round, note)
    } else {
        let mut fin = Finality::new(spec.ghostdag_k, spec.rounds_per_epoch);
        let genesis = Block::new(0, 0, vec![], spec.name.as_bytes().to_vec());
        let _ = fin.dag.insert(genesis);
        (fin, 0, "fresh start".to_string())
    };
    my_announcement.sync_hint = next_apply;
    let store = Store::open(&store_dir)?;

    let mut engine = bundle0.engine;
    let mut identity = bundle0.identity;
    let genesis_block = Block::new(0, 0, vec![], spec.name.as_bytes().to_vec());
    let genesis_id = genesis_block.id;

    // Network.
    let peer_key = load_or_create_peer_key(&dir)?;
    let mut net = NetNode::start(Some(peer_key), &args.listen).await?;
    let mut peer_addrs: Vec<libp2p::Multiaddr> = Vec::new();
    for p in &args.peers {
        let addr: libp2p::Multiaddr = p
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad --peer {p}: {e}")))?;
        let _ = net.dial(addr.clone());
        peer_addrs.push(addr);
    }
    let listen_addr = net
        .wait_listen_addr(Duration::from_secs(5))
        .await
        .map(|a| format!("{a}/p2p/{}", net.peer_id()))
        .unwrap_or_else(|| "unknown".to_string());
    println!("CHAIN {} genesis={}", spec.name, hex_encode(&spec.genesis_hash[..8]));
    println!("MACHINE {machine}");
    println!("LISTEN {listen_addr}");
    println!("START {sync_note}; ledger epoch {} minted {}", store.ledger().now, store.ledger().minted);

    // The first round this process will work on. A fresh node starts
    // at 0; an externally synced node starts at the bundle's round
    // (it has never acted, and replays forward). A SELF-resumed node
    // starts at the wall-clock round instead: it already proposed and
    // voted in the rounds since its last close, and re-proposing or
    // re-voting a round it already claimed — possibly for a different
    // block, from its rewound view — would be evidence against itself
    // under the one law. It treats those rounds as missed and rejoins
    // at the frontier.
    // Resume frontier: a full (finstate) resume processes rounds
    // SEQUENTIALLY from its apply point — jumping to the wall round
    // would skip rounds nobody proposed in during a total outage,
    // and sequential application could never cross them. Its
    // restored registries and canonical maps make re-processing
    // safe: rounds it already claimed come back as Duplicates. A
    // bundle-only resume keeps the wall jump: it has no working
    // state for the skipped rounds and must not re-claim them.
    let start_round = if full_resume {
        next_apply
    } else if self_resume {
        next_apply.max(spec.round_at(now_unix()))
    } else {
        next_apply
    };
    let synced = sync_path.is_some() || full_resume;
    let mut node = Node {
        spec,
        engine,
        identity,
        store,
        fin,
        net,
        peer_addrs,
        keys,
        my_announcement: my_announcement.clone(),
        announcements: BTreeMap::new(),
        pending_ann: Vec::new(),
        buffered_blocks: Vec::new(),
        buffered_votes: Vec::new(),
        pending_reveals: HashMap::new(),
        history_until: 0,
        catchup_from: None,
        heartbeats: HashMap::new(),
        hb_signed: HashSet::new(),
        next_apply,
        last_closed: None,
        join_inflight: None,
        genesis_id,
        collect_round: if synced { start_round + 1 } else { 0 },
        observe_until: if synced { Some(start_round) } else { None },
        bundle_synced: sync_path.is_some(),
        serve_cursor: 0,
        // A synced or resumed node must never vote for a round the
        // bundle already shows final: its target is chosen from its
        // own DAG view, and a late vote for a different block than
        // the finalized one is equivocation evidence against itself.
        voted: if synced { (0..=next_apply).collect() } else { HashSet::new() },
    };
    node.history_until = if synced {
        start_round + 2 * node.spec.rounds_per_epoch
    } else {
        node.spec.rounds_per_epoch
    };
    // Register bundle announcements (restores identity bindings), then self.
    for a in take_bundle_announcements() {
        node.register_announcement(&a, node.store.ledger().now);
    }
    let epoch_now = node.store.ledger().now;
    node.register_announcement(&my_announcement, epoch_now);
    let _ = node
        .net
        .publish(TOPIC_ACTS, framed(5, 0, &encode_announcement(&my_announcement)));

    if full_resume {
        // Rounds I already voted in (per the restored canonical
        // map) are marked voted: sequential re-processing must not
        // cast a second, different vote in any of them.
        for (r, _) in node.fin.canonical_votes(machine) {
            node.voted.insert(r);
        }
        // Re-cast my votes for rounds not yet final. The original
        // signatures may never have reached a peer before the
        // restart, and my round loop starts at the frontier, so
        // those rounds will never be re-processed by me. A re-cast
        // signs the SAME claim (same block, same round) with a fresh
        // one-time leaf: at every registry it is a Duplicate, never
        // evidence — it can only repair, never double-count.
        let mine = node.fin.canonical_votes(machine);
        for (round, block) in mine {
            if round >= node.next_apply && !node.fin.finalized.contains_key(&round) {
                if let Ok(sig) = node.keys.xmss.sign_persistent(&node.keys.xmss_path, &block) {
                    let vote = Vote { machine, round, block, sig };
                    let _ = node.fin.vote(vote.clone());
                    let _ = node
                        .net
                        .publish(TOPIC_VOTES, framed(3, round, &encode_vote(&vote)));
                    node.voted.insert(round);
                }
            }
        }
    }

    let mut rounds_done: u64 = 0;
    // Rounds are processed strictly in sequence, never skipped: the
    // round a node works on is its own counter, not the wall clock.
    // A node that falls behind (slow start, a heavy round) runs its
    // missed rounds back-to-back — process_round's timed pumps return
    // at once for rounds already past — until it catches up. Deriving
    // the round from the wall clock instead used to skip round 0
    // entirely on a node whose pre-genesis wait overshot t0: it never
    // closed round 0's committee, never cast round 0's vote, and the
    // chain stalled one vote short of finality forever.
    let mut next_round = start_round;
    loop {
        let now = now_unix();
        if now < node.spec.t0_unix {
            // Warm the gossip mesh before round 0: announce myself and
            // pump events so peers are connected when the chain starts.
            // Nonces are the wall-clock second: each republication is a
            // fresh gossip message, not a suppressed duplicate.
            for a in node.peer_addrs.clone() {
                let _ = node.net.dial(a);
            }
            let _ = node.net.publish(
                TOPIC_ACTS,
                framed(5, now, &encode_announcement(&node.my_announcement)),
            );
            // Round 0's reveals are collected during the wait (its
            // "previous round"), like every later round's during its
            // predecessor.
            if 1 < CHAIN_LEN {
                let link = node.keys.chain.reveal(1);
                let _ = node.fin.submit_reveal(node.keys.machine, 0, link);
                let _ = node
                    .net
                    .publish(TOPIC_BLOCKS, reveal_msg(node.keys.machine, 0, &link, now));
            }
            // Cap the wait pump at t0 itself: overshooting the
            // boundary used to make a node enter the round loop a
            // full round late.
            let until_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| (d.as_millis() + 4_000).min((node.spec.t0_unix as u128) * 1000))
                .unwrap_or(0);
            node.pump_until(until_ms).await;
            // Register what arrived during the wait and submit the
            // reveals that were buffered waiting for those
            // registrations, so round 0 opens with complete sets.
            let pending = std::mem::take(&mut node.pending_ann);
            for a in &pending {
                node.register_announcement(a, 0);
            }
            node.flush_reveals();
            continue;
        }
        let round = next_round;
        next_round += 1;
        node.process_round(round, &dir, &mut rng).await?;
        rounds_done += 1;
        if args.run_rounds > 0 && rounds_done >= args.run_rounds {
            println!(
                "DONE rounds={rounds_done} applied_through={} finalized_rounds={}",
                node.next_apply,
                node.fin.finalized.len()
            );
            return Ok(());
        }
    }
}

// Bundle announcements are handed from run_testnet's sync branch to the
// node through this slot (kept trivial: one bundle per process).
static BUNDLE_ANNS: std::sync::Mutex<Vec<Announcement>> = std::sync::Mutex::new(Vec::new());
fn pending_bundle_announcements(anns: Vec<Announcement>) {
    *BUNDLE_ANNS.lock().expect("lock") = anns;
}
fn take_bundle_announcements() -> Vec<Announcement> {
    std::mem::take(&mut *BUNDLE_ANNS.lock().expect("lock"))
}

impl Node {
    async fn pump_until(&mut self, deadline_ms: u128) {
        loop {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            if now_ms >= deadline_ms {
                return;
            }
            let step = ((deadline_ms - now_ms).min(200)) as u64;
            match tokio::time::timeout(Duration::from_millis(step), self.net.poll_once()).await {
                Ok(Some(inb)) => self.handle_inbound(inb),
                Ok(None) | Err(_) => {}
            }
        }
    }

    async fn process_round(
        &mut self,
        round: u64,
        dir: &Path,
        rng: &mut rand::rngs::ThreadRng,
    ) -> io::Result<()> {
        let rpe = self.spec.rounds_per_epoch;
        let epoch = round / rpe;
        // Keep configured peers connected (see peer_addrs).
        if round % 10 == 0 {
            for a in self.peer_addrs.clone() {
                let _ = self.net.dial(a);
            }
        }
        let start_ms = (self.spec.round_start_unix(round) as u128) * 1000;
        let d_ms = (self.spec.round_secs as u128) * 1000;
        let vote_at = start_ms + d_ms * 45 / 100;
        let round_end = start_ms + d_ms;
        // A freshly synced node observes its first round: it missed
        // that round's reveal collection, so it does not act in it.
        let mut observing = self.observe_until.map(|u| round <= u).unwrap_or(false);

        // Bound the retained history (see HISTORY_RETENTION_EPOCHS).
        self.fin
            .prune_before(round.saturating_sub(HISTORY_RETENTION_EPOCHS * rpe));
        // Registrations land at round boundaries only, so every node
        // samples committees from the same machine set.
        let pending = std::mem::take(&mut self.pending_ann);
        let mut new_machine = false;
        for a in &pending {
            if self.register_announcement(a, epoch) {
                new_machine = true;
                self.catchup_from = Some(match self.catchup_from {
                    Some(h) => h.min(a.sync_hint),
                    None => a.sync_hint,
                });
            }
        }
        if new_machine {
            // Someone may be catching up from a bundle: re-serve the
            // epoch history for the next two epochs.
            self.history_until = self.history_until.max(round + 2 * rpe);
        }
        // Re-announce myself (late joiners learn the machine set this
        // way). The sync hint tracks my CURRENT apply point, so peers
        // serve history from where I actually am, not from where I
        // first synced.
        let mut ann = self.my_announcement.clone();
        ann.sync_hint = self.next_apply;
        let _ = self
            .net
            .publish(TOPIC_ACTS, framed(5, round, &encode_announcement(&ann)));
        // Registrations just landed: submit the reveals that were
        // buffered waiting for them.
        self.flush_reveals();
        if !observing {
            // One last push of my own reveal for THIS round (fresh
            // nonce, so gossip actually forwards it) and of my recent
            // votes, then a short pump so peers' last pushes reach me,
            // and a final flush before the committee is sampled.
            if (round as usize) + 1 < CHAIN_LEN {
                let link = self.keys.chain.reveal((round + 1) as usize);
                let _ = self.fin.submit_reveal(self.keys.machine, round, link);
                let _ = self
                    .net
                    .publish(TOPIC_BLOCKS, reveal_msg(self.keys.machine, round, &link, round));
            }
            self.pump_until(start_ms + 300).await;
            self.flush_reveals();
        }

        // Catch-up dwell (bundle-synced nodes only): a round whose
        // wall-clock window has already passed gets no natural gossip
        // time, so its committee would close on whatever reveals
        // happen to be local — usually only this node's — and the
        // node would finalize a solo fork of the catch-up rounds
        // before the re-served history lands. Give the history a
        // bounded chance to arrive: dwell until a peer's reveal for
        // this round (or a peer's block in it) is in hand.
        if self.bundle_synced {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            if round_end <= now_ms {
                let dwell_end = now_ms + 2500;
                loop {
                    let have = self.announcements.keys().any(|m| {
                        *m != self.keys.machine && self.fin.reveal_of(*m, round).is_some()
                    }) || self
                        .fin
                        .dag
                        .blocks()
                        .iter()
                        .any(|b| b.round == round && b.machine != self.keys.machine);
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_millis())
                        .unwrap_or(0);
                    if have || now_ms >= dwell_end {
                        break;
                    }
                    self.pump_until((now_ms + 150).min(dwell_end)).await;
                }
            }
        }

        // Finality gate: this round's committee and proposer draws are
        // anchored to the finalized block of the round two back. Until
        // that block is final HERE, my beacon anchor differs from
        // settled nodes' anchors — so wait for it, pumping the network
        // and draining votes, up to the vote point. If it never lands,
        // observe this round: closing reveals now would freeze a
        // divergent committee into this node for the round (the close
        // is idempotent), and proposing or voting on a divergent anchor
        // only splits the round further.
        let mut settled = true;
        if round >= 2 {
            while !self.fin.finalized.contains_key(&(round - 2)) {
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis())
                    .unwrap_or(0);
                if now_ms >= vote_at {
                    break;
                }
                self.pump_until((now_ms + 150).min(vote_at)).await;
                let buffered = std::mem::take(&mut self.buffered_blocks);
                for b in buffered {
                    if !self.propose_guarded(b.clone()) && b.round >= round {
                        self.buffered_blocks.push(b);
                    }
                }
                self.drain_votes();
            }
            settled = self.fin.finalized.contains_key(&(round - 2));
            if !settled {
                observing = true;
            }
        }

        // The committee for THIS round is sampled now, from the links
        // revealed during the previous round — a full round of slack,
        // so honest nodes sample from the same reveal set.
        if settled {
            self.fin.close_round_reveals(round);
        }
        self.collect_round = round + 1;

        // Heartbeats for past epochs whose last round is now final.
        // The heartbeat message commits to the finalized tip of the
        // epoch's last round, so it can only be signed once that
        // round is final HERE — at the boundary round itself the last
        // round has not finalized yet (its votes are cast during the
        // boundary round), and signing then produces a signature over
        // the zero tip that no verifier accepts. Signing is therefore
        // not tied to a specific round: every round, sign each epoch
        // that has ended, is final, and is not yet signed.
        if !observing && !self.fin.is_revoked(self.keys.machine) {
            for e in 0..epoch {
                if self.hb_signed.contains(&e) {
                    continue;
                }
                if !self.fin.finalized.contains_key(&((e + 1) * rpe - 1)) {
                    continue;
                }
                let msg = self.fin.heartbeat_message(e);
                let sig = self.keys.device.sign(rng, &msg);
                self.heartbeats.insert((self.keys.machine, e), sig.clone());
                let _ = self
                    .net
                    .publish(TOPIC_VOTES, heartbeat_msg(self.keys.machine, e, &sig, round));
                self.hb_signed.insert(e);
            }
        }

        // Healing: re-publish the newest finalized block I hold, so a
        // peer that missed it (mesh gap) can complete its DAG — and
        // every block of the PREVIOUS round, the round this round's
        // votes target: a peer missing one of those would vote for a
        // different first block and split the round. Peers that already
        // hold a block drop the duplicate by content hash.
        let mut newest_final: Option<(u64, H512)> = None;
        for (r, b) in &self.fin.finalized {
            if newest_final.map(|(nr, _)| *r > nr).unwrap_or(true) {
                newest_final = Some((*r, *b));
            }
        }
        if let Some((_, bid)) = newest_final {
            if let Some(b) = self.fin.dag.get(&bid).cloned() {
                let _ = self.net.publish(TOPIC_BLOCKS, framed(2, round, &encode_block(&b)));
            }
        }
        if round >= 1 {
            for b in self.fin.dag.blocks().into_iter().filter(|b| b.round == round - 1) {
                let _ = self.net.publish(TOPIC_BLOCKS, framed(2, round, &encode_block(&b)));
            }
        }
        // Vote re-service: republish the accepted votes for the last
        // two rounds (a vote lost in the mesh is a stalled round at
        // small committee sizes) — and, while a recently joined or
        // resumed peer may be catching up, the whole current epoch's
        // history: blocks, reveals and votes for every round of the
        // epoch so far. A bundle covers a joiner up to the last epoch
        // close; this covers the rounds since.
        for vr in [round.wrapping_sub(1), round.wrapping_sub(2)] {
            for v in self.fin.votes_in_round(vr) {
                let _ = self.net.publish(TOPIC_VOTES, framed(3, round, &encode_vote(&v)));
            }
        }
        if round < self.history_until {
            // Serve from the oldest sync point a recent joiner
            // announced (rounded to its epoch start), clamped to the
            // retained-history floor — the joiner processes on its
            // own clock and lags the publisher's by an epoch or two,
            // so serving only the publisher's current epoch strands
            // it with subset committees and a solo fork.
            let floor = round.saturating_sub(HISTORY_RETENTION_EPOCHS * rpe);
            let from = match self.catchup_from {
                Some(h) => (h - (h % rpe)).max(floor),
                None => round - (round % rpe),
            };
            let machines: Vec<u64> = self.announcements.keys().copied().collect();
            // Walk the range in slices of 16 rounds per round: the
            // full range every round is thousands of republishes and
            // floods slow peers' queues; a joiner cycling the slices
            // still receives every round within a few rounds.
            let cur = if self.serve_cursor < from || self.serve_cursor >= round {
                from
            } else {
                self.serve_cursor
            };
            let end = (cur + 16).min(round);
            self.serve_cursor = end;
            for r in cur..end {
                for b in self.fin.dag.blocks().into_iter().filter(|b| b.round == r) {
                    let _ = self.net.publish(TOPIC_BLOCKS, framed(2, round, &encode_block(&b)));
                }
                for m in &machines {
                    if let Some(link) = self.fin.reveal_of(*m, r) {
                        let _ = self
                            .net
                            .publish(TOPIC_BLOCKS, reveal_msg(*m, r, &link, round));
                    }
                }
                for v in self.fin.votes_in_round(r) {
                    let _ = self.net.publish(TOPIC_VOTES, framed(3, round, &encode_vote(&v)));
                }
            }
        }

        if !observing && !self.fin.is_revoked(self.keys.machine) {
            // My reveal for NEXT round, collected during this one.
            if (round as usize) + 2 < CHAIN_LEN {
                let link = self.keys.chain.reveal((round + 2) as usize);
                let _ = self.fin.submit_reveal(self.keys.machine, round + 1, link);
                let _ = self.net.publish(
                    TOPIC_BLOCKS,
                    reveal_msg(self.keys.machine, round + 1, &link, round),
                );
            }
            // My proposal for THIS round (its reveal was collected
            // during the previous round; propose() checks the ticket).
            let mut ops: Vec<Op> = Vec::new();
            let joined = self.store.ledger().machines.contains(&self.keys.machine);
            if !joined && self.join_inflight.is_none() {
                let cm = h_u64("poe-join", &[Part::Bytes(&self.keys.device.public_key_bytes())]);
                let nf = h_u64("poe-join-nf", &[Part::Bytes(&self.keys.device.public_key_bytes())]);
                ops.push(Op::Join {
                    machine: self.keys.machine,
                    operator: self.keys.machine,
                    note: Note { cm, nf, asset: COIN, value: 1, born: 0 },
                });
            }
            // Re-processing a round I already proposed in (catch-up
            // after a resume): re-serve the canonical block, never
            // mint a second one — a different block for the same
            // (machine, round) claim is equivocation evidence
            // against me on every peer that kept the first.
            if let Some(existing) = self.fin.canonical_prop_of(self.keys.machine, round) {
                if let Some(b) = self.fin.dag.get(&existing).cloned() {
                    let _ = self
                        .net
                        .publish(TOPIC_BLOCKS, framed(2, round, &encode_block(&b)));
                }
                // fall through to the vote step without proposing
            } else {
            let parents = self.fin.dag.tips();
            let block = Block::new(self.keys.machine, round, parents, ops_payload(&ops));
            match self.fin.propose(block.clone()) {
                Ok(poe_kernel::ClaimOutcome::Accepted) => {
                    if !ops.is_empty() {
                        self.join_inflight = Some(round);
                    }
                    let _ = self
                        .net
                        .publish(TOPIC_BLOCKS, framed(2, round, &encode_block(&block)));
                }
                Ok(_) => {}
                Err(_) => {}
            }
            }
        }
        self.pump_until(vote_at).await;
        // Buffered blocks get another chance now that more of the DAG
        // and more registrations have landed.
        let buffered = std::mem::take(&mut self.buffered_blocks);
        for b in buffered {
            if !self.propose_guarded(b.clone()) && b.round >= round {
                self.buffered_blocks.push(b);
            }
        }
        self.flush_reveals();
        self.drain_votes();

        // Catch-up vote settle: on a round whose wall window has
        // already passed, the previous round's proposals may still
        // be in flight between peers that are themselves catching
        // up. Voting on a partial view splits a small committee's
        // votes across different blocks, and a split round never
        // finalizes. At the frontier the round's own duration
        // prevents this; in catch-up, dwell briefly for the
        // proposals to settle — until blocks from at least two
        // distinct machines for the target round are in the DAG,
        // or a bounded time passes.
        if round >= 1 {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            if round_end <= now_ms {
                let target_round = round - 1;
                let dwell_end = now_ms + 800;
                loop {
                    let proposers: HashSet<u64> = self
                        .fin
                        .dag
                        .blocks()
                        .iter()
                        .filter(|b| b.round == target_round)
                        .map(|b| b.machine)
                        .collect();
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_millis())
                        .unwrap_or(0);
                    if proposers.len() >= 2 || now_ms >= dwell_end {
                        break;
                    }
                    self.pump_until((now_ms + 120).min(dwell_end)).await;
                }
                self.drain_votes();
            }
        }

        // My vote — for the PREVIOUS round. The one-round lag means
        // every honest node votes on a converged view of that round's
        // blocks, as in the Step-4 simnet's delayed delivery.
        if round >= 1 && !observing {
            let target_round = round - 1;
            if !self.voted.contains(&target_round) {
                self.voted.insert(target_round);
                let in_committee = self
                    .fin
                    .committee(target_round)
                    .map(|c| c.contains(&self.keys.machine))
                    .unwrap_or(false);
                if in_committee && !self.fin.is_revoked(self.keys.machine) {
                    let order = self.fin.dag.linearize();
                    let target = order.iter().find(|id| {
                        **id != self.genesis_id
                            && self.fin.dag.get(id).map(|b| b.round) == Some(target_round)
                    });
                    if let Some(target) = target {
                        if std::env::var_os("POE_DEBUG").is_some() {
                            println!(
                                "DBG r={round} vote_target r{}={}",
                                target_round,
                                hex_encode(&target[..8])
                            );
                        }
                        if let Ok(sig) =
                            self.keys.xmss.sign_persistent(&self.keys.xmss_path, target)
                        {
                            let vote =
                                Vote { machine: self.keys.machine, round: target_round, block: *target, sig };
                            let body = encode_vote(&vote);
                            let _ = self.net.publish(TOPIC_VOTES, framed(3, round, &body));
                            let _ = self.fin.vote(vote);
                        }
                    }
                }
            }
        }
        self.pump_until(round_end).await;
        self.flush_reveals();
        self.drain_votes();
        self.apply_finalized()?;
        if std::env::var_os("POE_DEBUG").is_some() {
            let tally: Vec<String> = if round >= 1 {
                self.fin
                    .vote_tally(round - 1)
                    .iter()
                    .map(|(b, n)| format!("{}:{}", hex_encode(&b[..4]), n))
                    .collect()
            } else {
                Vec::new()
            };
            println!(
                "DBG r={round} machines={} comm={} anchor={} tally_prev=[{}] fin={} applied={}",
                self.fin.active_count(),
                self.fin.committee(round).map(|c| c.len()).unwrap_or(0),
                hex_encode(&self.fin.beacon_reference(round)[..4]),
                tally.join(","),
                self.fin.finalized.len(),
                self.next_apply
            );
        }

        // My join landing check: the inflight marker clears only when
        // the join is actually IN the ledger. (It used to clear once
        // the proposing round had been applied locally — on a view
        // that had diverged, that silently retired a join that had
        // never landed on the real chain.)
        if self.join_inflight.is_some()
            && self.store.ledger().machines.contains(&self.keys.machine)
        {
            self.join_inflight = None;
        }
        // Orphaned-join retry: if the round that carried my join
        // proposal is FINAL and the join still isn't in the ledger,
        // the proposal lost (not the GHOSTDAG winner, or its round's
        // votes went elsewhere) — clear the marker so a later round
        // re-proposes. Without this, one lost proposal retired the
        // join forever (join_inflight only ever cleared on success).
        if let Some(proposed_at) = self.join_inflight {
            if self.fin.finalized.contains_key(&proposed_at)
                && !self.store.ledger().machines.contains(&self.keys.machine)
            {
                self.join_inflight = None;
            }
        }
        // Closes: every epoch strictly before the current one whose
        // rounds are all applied — and never in the epoch's first
        // round after the boundary: heartbeats for the epoch are only
        // signed once its last round is final (during the following
        // round at the earliest), and they need that round to reach
        // peers before the close counts them.
        let mut e = self.last_closed.map(|l| l + 1).unwrap_or(0);
        while e < epoch {
            if self.next_apply >= (e + 1) * rpe && round >= (e + 1) * rpe + 1 {
                self.try_close(e, dir)?;
            }
            e += 1;
        }
        // Persist the full finality state for restart resume. A
        // failed write only degrades resume freshness (the epoch
        // bundle remains as fallback), so it never fails the round.
        let _ = write_finstate(&dir.join("finstate.bin"), &self.fin, self.next_apply);
        Ok(())
    }
}
