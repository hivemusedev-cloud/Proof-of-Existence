//! poe-store — the PoE storage layer (BUILD_FLOW Step 3).
//!
//! Backend, stated plainly: an append-only act log plus atomic snapshots
//! over the canonical encoding in [`encode`], behind the `Store` API. The
//! API — not the file format — is the contract the networking and finality
//! layers will consume; a RocksDB backend can replace the files behind it
//! without touching callers (its C++ build is deliberately not pulled into
//! this workspace yet).
//!
//! What lives here:
//! * the act log: every applied act, length-framed with a checksum; replay
//!   on open rebuilds the ledger, and a torn tail (a crash mid-write) is
//!   detected and dropped, never applied;
//! * snapshots: the full ledger + state-root chain, written atomically
//!   (temp file + rename), after which the log restarts;
//! * per-epoch **state roots**: at every close, `H("state-root", …)` over
//!   the previous root, epoch, minted, live coin, a running births
//!   accumulator, and set sizes — the commitment the storage challenge
//!   answers from;
//! * pruning support: [`Store::prune_and_snapshot`] swaps the ledger for
//!   its `pruned()` form; the state-root chain is untouched by pruning, so
//!   roots stay comparable between pruned and full nodes;
//! * registry persistence and the nullifier [`filter`].

pub mod encode;
pub mod filter;

use encode::{decode_ledger, decode_op, encode_ledger, encode_op, Reader, Writer};
use poe_crypto::hash::{h, Part, H512};
use poe_kernel::ledger::{Ledger, Op};
use poe_kernel::{ClaimOutcome, Registry, RegistryKind, Spend};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

fn checksum(payload: &[u8], tag: &str) -> [u8; 8] {
    let d = h(tag, &[Part::Bytes(payload)]);
    d[..8].try_into().expect("64-byte digest")
}

fn fold_birth(acc: H512, n: &poe_kernel::ledger::Note) -> H512 {
    h(
        "births-acc",
        &[
            Part::Bytes(&acc),
            Part::Nat(n.cm),
            Part::Nat(n.nf),
            Part::Nat(n.asset),
            Part::Nat(n.value),
            Part::Nat(n.born),
        ],
    )
}

pub struct Store {
    dir: PathBuf,
    ledger: Ledger,
    log: BufWriter<File>,
    roots: Vec<(u64, H512)>,
    births_acc: H512,
    births_len: usize,
}

impl Store {
    /// Open (or create) a store in `dir`: load the snapshot if one exists,
    /// then replay the act log on top of it. A torn or corrupt log tail is
    /// dropped at the first bad record.
    pub fn open(dir: &Path) -> io::Result<Store> {
        fs::create_dir_all(dir)?;
        let snap_path = dir.join("ledger.snapshot");
        let (mut ledger, mut roots, mut births_acc) = if snap_path.exists() {
            let raw = fs::read(&snap_path)?;
            let (payload, ck) = raw.split_at(raw.len().saturating_sub(8));
            if ck != checksum(payload, "snapshot") {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "snapshot checksum"));
            }
            let mut r = Reader::new(payload);
            let ledger = decode_ledger(&mut r)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "snapshot ledger"))?;
            let acc_bytes = r.bytes(64).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "snapshot acc"))?;
            let mut acc = [0u8; 64];
            acc.copy_from_slice(acc_bytes);
            let nr = r
                .u32()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "snapshot roots"))?
                as usize;
            let mut roots = Vec::with_capacity(nr);
            for _ in 0..nr {
                let e = r
                    .u64()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "snapshot root epoch"))?;
                let rb = r.bytes(64).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "snapshot root"))?;
                let mut root = [0u8; 64];
                root.copy_from_slice(rb);
                roots.push((e, root));
            }
            (ledger, roots, acc)
        } else {
            (Ledger::genesis(), Vec::new(), h("births-acc-empty", &[]))
        };

        let log_path = dir.join("ops.log");
        let mut births_len = ledger.births.len();
        if roots.is_empty() && births_len > 0 && !snap_path.exists() {
            // Fresh genesis: fold its reserve birth into the accumulator.
            for n in &ledger.births.clone() {
                births_acc = fold_birth(births_acc, n);
            }
        }
        if log_path.exists() {
            let raw = fs::read(&log_path)?;
            let mut pos = 0usize;
            while pos + 4 <= raw.len() {
                let len = u32::from_be_bytes(raw[pos..pos + 4].try_into().unwrap()) as usize;
                let end = pos + 4 + len + 8;
                if end > raw.len() {
                    break; // torn tail
                }
                let payload = &raw[pos + 4..pos + 4 + len];
                if raw[pos + 4 + len..end] != checksum(payload, "logrec") {
                    break; // corrupt record: drop it and everything after
                }
                let mut r = Reader::new(payload);
                let Some(op) = decode_op(&mut r) else { break };
                ledger = ledger.act(&op);
                let new_len = ledger.births.len();
                if new_len > births_len {
                    for n in &ledger.births[..new_len - births_len] {
                        births_acc = fold_birth(births_acc, n);
                    }
                }
                births_len = new_len;
                if let Op::Tick { .. } = op {
                    let root = state_root(&ledger, &roots, &births_acc);
                    roots.push((ledger.now, root));
                }
                pos = end;
            }
        }

        let log_file = OpenOptions::new().create(true).append(true).open(&log_path)?;
        Ok(Store {
            dir: dir.to_path_buf(),
            ledger,
            log: BufWriter::new(log_file),
            roots,
            births_acc,
            births_len,
        })
    }

    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// The state roots of all closed epochs, in order.
    pub fn roots(&self) -> &[(u64, H512)] {
        &self.roots
    }

    pub fn state_root_at(&self, epoch: u64) -> Option<H512> {
        self.roots.iter().find(|(e, _)| *e == epoch).map(|(_, r)| *r)
    }

    /// Apply one act: update the ledger, fold any new births into the
    /// accumulator, append the act to the log, and — at a close — record
    /// the epoch's state root and flush (the epoch is the durability
    /// point; mid-epoch acts flush on [`Store::flush`] or the next close).
    pub fn apply(&mut self, op: &Op) -> io::Result<()> {
        let payload = encode_op(op);
        let mut rec = Vec::with_capacity(payload.len() + 12);
        rec.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        rec.extend_from_slice(&payload);
        rec.extend_from_slice(&checksum(&payload, "logrec"));
        self.log.write_all(&rec)?;

        self.ledger = self.ledger.act(op);
        let new_len = self.ledger.births.len();
        if new_len > self.births_len {
            for n in &self.ledger.births.clone()[..new_len - self.births_len] {
                self.births_acc = fold_birth(self.births_acc, n);
            }
        }
        self.births_len = new_len;
        if let Op::Tick { .. } = op {
            let root = state_root(&self.ledger, &self.roots, &self.births_acc);
            self.roots.push((self.ledger.now, root));
            self.flush()?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.log.flush()
    }

    /// Write an atomic snapshot of the current state and restart the log.
    pub fn snapshot(&mut self) -> io::Result<()> {
        self.flush()?;
        let mut w = Writer::new();
        w.bytes(&encode_ledger(&self.ledger));
        w.bytes(&self.births_acc);
        w.u32(self.roots.len() as u32);
        for (e, r) in &self.roots {
            w.u64(*e);
            w.bytes(r);
        }
        let payload = w.0;
        let mut file_bytes = payload.clone();
        file_bytes.extend_from_slice(&checksum(&payload, "snapshot"));
        let tmp = self.dir.join("ledger.snapshot.tmp");
        write_synced(&tmp, &file_bytes)?;
        fs::rename(&tmp, self.dir.join("ledger.snapshot"))?;
        // Restart the log: the snapshot now carries everything it held.
        self.log = BufWriter::new(
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(self.dir.join("ops.log"))?,
        );
        Ok(())
    }

    /// Replace the ledger by its window-pruned form and snapshot. State
    /// roots are history commitments and are NOT pruned: a pruned node and
    /// a full node that saw the same history hold the same roots.
    pub fn prune_and_snapshot(&mut self) -> io::Result<()> {
        self.ledger = self.ledger.pruned();
        self.births_len = self.ledger.births.len();
        self.snapshot()
    }
}

fn state_root(ledger: &Ledger, roots: &[(u64, H512)], births_acc: &H512) -> H512 {
    let prev = roots
        .last()
        .map(|(_, r)| *r)
        .unwrap_or_else(|| h("state-root-genesis", &[]));
    let live = poe_kernel::ledger::live_a(ledger, poe_kernel::COIN);
    h(
        "state-root",
        &[
            Part::Bytes(&prev),
            Part::Nat(ledger.now),
            Part::Nat(ledger.minted as u64),
            Part::Nat(live as u64),
            Part::Bytes(births_acc),
            Part::Nat(ledger.machines.len() as u64),
            Part::Nat(ledger.deaths.len() as u64),
            Part::Nat(ledger.births.len() as u64),
        ],
    )
}

// -- registry persistence -----------------------------------------------------

fn kind_tag(k: RegistryKind) -> u8 {
    match k {
        RegistryKind::CoinDeath => 0,
        RegistryKind::MachineBirth => 1,
        RegistryKind::Vote => 2,
        RegistryKind::KeyUse => 3,
        RegistryKind::Slot => 4,
        RegistryKind::Proposal => 5,
        RegistryKind::Admission => 6,
        RegistryKind::ContractVersion => 7,
        RegistryKind::OracleTick => 8,
        RegistryKind::MessageTag => 9,
    }
}

fn tag_kind(t: u8) -> Option<RegistryKind> {
    Some(match t {
        0 => RegistryKind::CoinDeath,
        1 => RegistryKind::MachineBirth,
        2 => RegistryKind::Vote,
        3 => RegistryKind::KeyUse,
        4 => RegistryKind::Slot,
        5 => RegistryKind::Proposal,
        6 => RegistryKind::Admission,
        7 => RegistryKind::ContractVersion,
        8 => RegistryKind::OracleTick,
        9 => RegistryKind::MessageTag,
        _ => return None,
    })
}

/// Persist all ten registries (or any subset) to `dir/registries.bin`.
/// Write bytes and fsync on the SAME writable handle. (Opening the
/// file read-only afterwards to fsync it works on Linux but is Access
/// Denied on Windows, where FlushFileBuffers needs write access.)
fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = File::create(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

pub fn save_registries(dir: &Path, regs: &[Registry]) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let mut w = Writer::new();
    w.u32(regs.len() as u32);
    for r in regs {
        w.u8(kind_tag(r.kind));
        w.u64s(r.heights());
        w.u32(r.accepted().len() as u32);
        for s in r.accepted() {
            w.spend(s);
        }
        w.u32(r.evidence().len() as u32);
        for (a, b) in r.evidence() {
            w.spend(a);
            w.spend(b);
        }
    }
    let payload = w.0;
    let mut file_bytes = payload.clone();
    file_bytes.extend_from_slice(&checksum(&payload, "registries"));
    let tmp = dir.join("registries.bin.tmp");
    write_synced(&tmp, &file_bytes)?;
    fs::rename(&tmp, dir.join("registries.bin"))?;
    Ok(())
}

/// Load registries saved by [`save_registries`].
pub fn load_registries(dir: &Path) -> io::Result<Vec<Registry>> {
    let raw = fs::read(dir.join("registries.bin"))?;
    let (payload, ck) = raw.split_at(raw.len().saturating_sub(8));
    if ck != checksum(payload, "registries") {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "registries checksum"));
    }
    let mut r = Reader::new(payload);
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "registries decode");
    let n = r.u32().ok_or_else(bad)? as usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let kind = tag_kind(r.u8().ok_or_else(bad)?).ok_or_else(bad)?;
        let heights = r.u64s().ok_or_else(bad)?;
        let na = r.u32().ok_or_else(bad)? as usize;
        let mut accepted = Vec::with_capacity(na);
        for _ in 0..na {
            accepted.push(r.spend().ok_or_else(bad)?);
        }
        let ne = r.u32().ok_or_else(bad)? as usize;
        let mut evidence = Vec::with_capacity(ne);
        for _ in 0..ne {
            let a = r.spend().ok_or_else(bad)?;
            let b = r.spend().ok_or_else(bad)?;
            evidence.push((a, b));
        }
        out.push(Registry::restore(kind, heights, accepted, evidence));
    }
    Ok(out)
}

/// Convenience: what a claim decided, re-exported for store callers.
pub type Claim = ClaimOutcome;

/// A spend as stored: re-export to keep callers on one import path.
pub type StoredSpend = Spend;
