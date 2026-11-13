//! Canonical byte encoding for kernel values.
//!
//! Fixed-width big-endian, counts as u32, no padding, no platform variance:
//! the same value encodes to the same bytes on every machine, forever —
//! the storage layer, the act log, and the state roots all depend on it.

use poe_kernel::ledger::{AssetRec, Ledger, Note, Op};
use poe_kernel::Spend;

pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn new() -> Writer {
        Writer(Vec::new())
    }
    pub fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    pub fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    pub fn u128(&mut self, v: u128) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    pub fn u64s(&mut self, vs: &[u64]) {
        self.u32(vs.len() as u32);
        for v in vs {
            self.u64(*v);
        }
    }
    pub fn note(&mut self, n: &Note) {
        self.u64(n.cm);
        self.u64(n.nf);
        self.u64(n.asset);
        self.u64(n.value);
        self.u64(n.born);
    }
    pub fn notes(&mut self, ns: &[Note]) {
        self.u32(ns.len() as u32);
        for n in ns {
            self.note(n);
        }
    }
    pub fn spend(&mut self, s: &Spend) {
        self.u64(s.tx);
        self.u64(s.nf);
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }
    pub fn is_done(&self) -> bool {
        self.pos == self.buf.len()
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.buf.get(self.pos..self.pos + n)?;
        self.pos += n;
        Some(s)
    }
    pub fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    pub fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
    pub fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }
    pub fn u128(&mut self) -> Option<u128> {
        Some(u128::from_be_bytes(self.take(16)?.try_into().ok()?))
    }
    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        self.take(n)
    }
    pub fn u64s(&mut self) -> Option<Vec<u64>> {
        let n = self.u32()? as usize;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.u64()?);
        }
        Some(out)
    }
    pub fn note(&mut self) -> Option<Note> {
        Some(Note {
            cm: self.u64()?,
            nf: self.u64()?,
            asset: self.u64()?,
            value: self.u64()?,
            born: self.u64()?,
        })
    }
    pub fn notes(&mut self) -> Option<Vec<Note>> {
        let n = self.u32()? as usize;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.note()?);
        }
        Some(out)
    }
    pub fn spend(&mut self) -> Option<Spend> {
        Some(Spend {
            tx: self.u64()?,
            nf: self.u64()?,
        })
    }
}

pub fn encode_op(op: &Op) -> Vec<u8> {
    let mut w = Writer::new();
    match op {
        Op::Join { machine, operator, note } => {
            w.u8(0);
            w.u64(*machine);
            w.u64(*operator);
            w.note(note);
        }
        Op::Renew { machine, operator, note } => {
            w.u8(1);
            w.u64(*machine);
            w.u64(*operator);
            w.note(note);
        }
        Op::Create { issuer, asset, cap } => {
            w.u8(2);
            w.u64(*issuer);
            w.u64(*asset);
            w.u128(*cap);
        }
        Op::Issue { issuer, asset, outs } => {
            w.u8(3);
            w.u64(*issuer);
            w.u64(*asset);
            w.notes(outs);
        }
        Op::Transfer { ins, outs } => {
            w.u8(4);
            w.notes(ins);
            w.notes(outs);
        }
        Op::Tick { cap } => {
            w.u8(5);
            w.u64(*cap);
        }
    }
    w.0
}

pub fn decode_op(r: &mut Reader) -> Option<Op> {
    let op = match r.u8()? {
        0 => Op::Join {
            machine: r.u64()?,
            operator: r.u64()?,
            note: r.note()?,
        },
        1 => Op::Renew {
            machine: r.u64()?,
            operator: r.u64()?,
            note: r.note()?,
        },
        2 => Op::Create {
            issuer: r.u64()?,
            asset: r.u64()?,
            cap: r.u128()?,
        },
        3 => Op::Issue {
            issuer: r.u64()?,
            asset: r.u64()?,
            outs: r.notes()?,
        },
        4 => Op::Transfer {
            ins: r.notes()?,
            outs: r.notes()?,
        },
        5 => Op::Tick { cap: r.u64()? },
        _ => return None,
    };
    Some(op)
}

pub fn encode_ledger(l: &Ledger) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(l.now);
    w.u64s(&l.machines);
    w.notes(&l.births);
    w.u64s(&l.deaths);
    w.u128(l.minted);
    w.u32(l.assets.len() as u32);
    for a in &l.assets {
        w.u64(a.id);
        w.u64(a.issuer);
        w.u128(a.cap);
    }
    w.notes(&l.issues);
    w.notes(&l.regs);
    w.u64s(&l.claimants);
    w.0
}

pub fn decode_ledger(r: &mut Reader) -> Option<Ledger> {
    let now = r.u64()?;
    let machines = r.u64s()?;
    let births = r.notes()?;
    let deaths = r.u64s()?;
    let minted = r.u128()?;
    let na = r.u32()? as usize;
    let mut assets = Vec::with_capacity(na);
    for _ in 0..na {
        assets.push(AssetRec {
            id: r.u64()?,
            issuer: r.u64()?,
            cap: r.u128()?,
        });
    }
    let issues = r.notes()?;
    let regs = r.notes()?;
    let claimants = r.u64s()?;
    Some(Ledger {
        now,
        machines,
        births,
        deaths,
        minted,
        assets,
        issues,
        regs,
        claimants,
    })
}
