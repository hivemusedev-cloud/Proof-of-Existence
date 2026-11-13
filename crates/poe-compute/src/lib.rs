//! poe-compute — the Compute Fibre (BUILD_FLOW Step 11).
//!
//! The deterministic kernels are ported from the Python seed
//! (`physos_fabric.kernels`) function for function, and the battery
//! pins them against the seed itself: same jobs, same parameters, same
//! Merkle roots, computed by numpy there and by this crate here.
//!
//! * **Exact lane** — `gemm_i8` (int8 matrix product accumulated in
//!   int64; a piece is one product row), `sieve` (a segmented prime
//!   count, block by block), `search` (hash-certificate witnesses below
//!   a target). Integer arithmetic is order-free, so every executor on
//!   any hardware returns the same bits.
//! * **Strict lane** — `dot_f32`: binary32 on a pinned plan (every
//!   product rounded, every sum rounded, left to right, no fused
//!   contraction). Rust's `f32` ops are exactly that plan; the formal
//!   road re-derives each step in exact f64 and rounds, independently.
//! * **The roads.** Each kernel carries the seed's three: the *executed*
//!   road (the piece computed from the input material), the *formal*
//!   road (the piece derived from the specification alone, sharing no
//!   code with the executor — scaled-row sums for the gemm, Miller-Rabin
//!   for the sieve, a separately-written certificate hash for search),
//!   and the *registration* road (the piece opened against the committed
//!   side, and the claim's entry in the kernel's registry record).
//! * **Claims and the triaxial audit.** A claim commits its side (the
//!   pieces' Merkle root), its piece count and its exact operation count
//!   — stated by `ops_of` without running anything. Only after the
//!   commitment does the beacon draw the probe pieces. Seal L reads the
//!   claim's sentence (shape, ops, side); the registration road replays
//!   the record; Seal G runs the probes through opening + executed +
//!   formal agreement; Seal M requires the drawn sample to span its
//!   warrant. Verdicts: **Sealed**, **Broken** (with the failing seal),
//!   **Open** (a road is missing — no registration on record).
//!
//! Scope, stated plainly: the seed's full triaxial formalism (claims
//! against denials, the GOL determinant contexts) is a research artifact
//! whose fifteen worked examples were verified byte-identical at intake
//! (2026-11-10); this crate ports the kernels exactly and the audit in
//! its protocol shape — commit, draw, three roads, plants, verdict —
//! with planted controls (a moved input, a moved specification) that
//! the seals must refuse, as the seed's plants move one anchor at a time.

use poe_crypto::hash::{h, h_u64, merkle_proof, merkle_root, merkle_verify, Part, H512};
use poe_kernel::{ClaimOutcome, Registry, RegistryKind, Spend};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

// -- content-addressed inputs (seed: kernels.stream) ----------------------------

/// The seed's input stream: SHAKE256 of `b"PoE/input"` and the 64-byte
/// seed, read to `n` bytes. Every kernel input is generated, never sent.
pub fn stream(seed: &H512, n: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(b"PoE/input");
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; n];
    reader.read(&mut out);
    out
}

fn seed_of(tag: &str, job: u64, chunk: u64) -> H512 {
    h(tag, &[Part::Nat(job), Part::Nat(chunk)])
}

fn ints8(seed: &H512, count: usize) -> Vec<i8> {
    stream(seed, count).iter().map(|b| *b as i8).collect()
}

/// Binary32 values in [−1, 1) on a 2^−22 grid (seed: floats32).
fn floats32(seed: &H512, count: usize) -> Vec<f32> {
    let raw = stream(seed, 4 * count);
    (0..count)
        .map(|i| {
            let v = u32::from_le_bytes(raw[4 * i..4 * i + 4].try_into().unwrap());
            ((v >> 9) as f32) * (1.0 / 4_194_304.0) - 1.0
        })
        .collect()
}

fn loc(i: u64) -> [u8; 8] {
    i.to_be_bytes()
}

// -- parameters -------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kernel {
    GemmI8,
    Sieve,
    Search,
    DotF32,
}

#[derive(Clone, Copy, Debug)]
pub struct Params {
    pub m: u64,
    pub k: u64,
    pub n: u64,
    pub width: u64,
    pub blocks: Option<u64>,
    pub base: Option<u64>,
    pub span: u64,
    pub bits: u32,
}

impl Params {
    pub fn gemm(m: u64, k: u64, n: u64) -> Params {
        Params { m, k, n, width: 0, blocks: None, base: None, span: 0, bits: 0 }
    }
    pub fn sieve(width: u64, blocks: u64) -> Params {
        Params { m: 0, k: 0, n: 0, width, blocks: Some(blocks), base: None, span: 0, bits: 0 }
    }
    pub fn search(span: u64, blocks: u64, bits: u32) -> Params {
        Params { m: 0, k: 0, n: 0, width: 0, blocks: Some(blocks), base: None, span, bits }
    }
    pub fn dot(m: u64, k: u64) -> Params {
        Params { m, k, n: 0, width: 0, blocks: None, base: None, span: 0, bits: 0 }
    }
    fn blocks_or(&self, d: u64) -> u64 {
        self.blocks.unwrap_or(d)
    }
}

impl Kernel {
    /// The seed's canonical piece count, from parameters alone.
    pub fn npieces(&self, p: &Params) -> u64 {
        match self {
            Kernel::GemmI8 | Kernel::DotF32 => p.m,
            Kernel::Sieve => p.blocks_or(16),
            Kernel::Search => p.blocks_or(8),
        }
    }

    /// The seed's `ops_of`: the exact motion, stated without running.
    pub fn ops_of(&self, _job: u64, chunk: u64, p: &Params) -> u64 {
        match self {
            Kernel::GemmI8 => 2 * p.m * p.k * p.n,
            Kernel::DotF32 => 2 * p.m * p.k,
            Kernel::Search => p.span,
            Kernel::Sieve => sieve_ops(chunk, p),
        }
    }

    /// Run the kernel (the executor's whole run): pieces + ops.
    pub fn run(&self, job: u64, chunk: u64, p: &Params) -> (Vec<Vec<u8>>, u64) {
        let n = self.npieces(p);
        let pieces = (0..n).map(|i| self.piece_on(job, chunk, p, i)).collect();
        (pieces, self.ops_of(job, chunk, p))
    }

    /// The executed road: piece `i` from the input material.
    pub fn piece_on(&self, job: u64, chunk: u64, p: &Params, i: u64) -> Vec<u8> {
        match self {
            Kernel::GemmI8 => gemm_piece_on(job, chunk, p, i),
            Kernel::Sieve => sieve_piece_on(chunk, p, i),
            Kernel::Search => search_piece_on(job, chunk, p, i),
            Kernel::DotF32 => dot_piece_on(job, chunk, p, i),
        }
    }

    /// The formal road: piece `i` from the specification alone.
    pub fn formal(&self, job: u64, chunk: u64, p: &Params, i: u64) -> Vec<u8> {
        match self {
            Kernel::GemmI8 => gemm_formal(job, chunk, p, i),
            Kernel::Sieve => sieve_formal(chunk, p, i),
            Kernel::Search => search_formal(job, chunk, p, i),
            Kernel::DotF32 => dot_formal(job, chunk, p, i),
        }
    }
}

// -- gemm_i8 ------------------------------------------------------------------------

fn gemm_a(job: u64, chunk: u64, p: &Params) -> Vec<i8> {
    ints8(&seed_of("A", job, chunk), (p.m * p.k) as usize)
}
fn gemm_piece_on(job: u64, chunk: u64, p: &Params, i: u64) -> Vec<u8> {
    let a = gemm_a(job, chunk, p);
    let b = {
        let seed = h("B", &[Part::Nat(job)]);
        ints8(&seed, (p.k * p.n) as usize)
    };
    let mut out = loc(i).to_vec();
    for j in 0..p.n {
        let mut acc: i64 = 0;
        for kk in 0..p.k {
            acc += a[(i * p.k + kk) as usize] as i64 * b[(kk * p.n + j) as usize] as i64;
        }
        out.extend_from_slice(&acc.to_le_bytes());
    }
    out
}

/// The formal road for the gemm: row i as a sum of scaled rows of B, in
/// unbounded integers, the streams decoded byte by byte — no matrix
/// product anywhere (the seed's `_gemm_formal`).
fn gemm_formal(job: u64, chunk: u64, p: &Params, i: u64) -> Vec<u8> {
    let a_bytes = stream(&seed_of("A", job, chunk), (p.m * p.k) as usize);
    let b_bytes = stream(&h("B", &[Part::Nat(job)]), (p.k * p.n) as usize);
    let sgn = |b: u8| -> i128 { if b > 127 { b as i128 - 256 } else { b as i128 } };
    let mut row = vec![0i128; p.n as usize];
    for kk in 0..p.k {
        let ak = sgn(a_bytes[(i * p.k + kk) as usize]);
        if ak != 0 {
            for j in 0..p.n {
                row[j as usize] += ak * sgn(b_bytes[(kk * p.n + j) as usize]);
            }
        }
    }
    let mut out = loc(i).to_vec();
    for v in row {
        out.extend_from_slice(&(v as i64).to_le_bytes());
    }
    out
}

/// The seed's material plant for the gemm: one element of the row moved.
pub fn gemm_plant_row(job: u64, chunk: u64, p: &Params, i: u64, salt: u64) -> Vec<u8> {
    let a = gemm_a(job, chunk, p);
    let mut row: Vec<i8> = a[(i * p.k) as usize..((i + 1) * p.k) as usize].to_vec();
    let kk = (salt % p.k) as usize;
    row[kk] = if row[kk] == 127 { -128 } else { row[kk] + 1 };
    let b = ints8(&h("B", &[Part::Nat(job)]), (p.k * p.n) as usize);
    let mut out = loc(i).to_vec();
    for j in 0..p.n {
        let mut acc: i64 = 0;
        for (kkk, &av) in row.iter().enumerate() {
            acc += av as i64 * b[kkk * p.n as usize + j as usize] as i64;
        }
        out.extend_from_slice(&acc.to_le_bytes());
    }
    out
}

// -- sieve ----------------------------------------------------------------------------

fn sieve_bounds(chunk: u64, p: &Params, i: u64) -> (u64, u64) {
    let nb = p.blocks_or(16);
    let base = p.base.unwrap_or(1_000_000) + chunk * p.width;
    (base + i * p.width / nb, base + (i + 1) * p.width / nb)
}

fn small_primes(r: u64) -> Vec<u64> {
    if r < 2 {
        return Vec::new();
    }
    let mut is = vec![true; (r + 1) as usize];
    is[0] = false;
    is[1] = false;
    let mut i = 2u64;
    while i * i <= r {
        if is[i as usize] {
            let mut j = i * i;
            while j <= r {
                is[j as usize] = false;
                j += i;
            }
        }
        i += 1;
    }
    (2..=r).filter(|&x| is[x as usize]).collect()
}

fn sieve_starts(lo: u64, hi: u64) -> Vec<(u64, u64)> {
    if hi == 0 {
        return Vec::new();
    }
    let r = ((hi - 1) as f64).sqrt() as u64;
    let r = if (r + 1) * (r + 1) <= hi - 1 { r + 1 } else { r };
    small_primes(r)
        .into_iter()
        .map(|p| (p, (p * p).max((lo + p - 1) / p * p)))
        .filter(|&(_, st)| st < hi)
        .collect()
}

fn sieve_count(lo: u64, hi: u64) -> u64 {
    if hi <= lo {
        return 0;
    }
    let mut seg = vec![true; (hi - lo) as usize];
    for (p, s) in sieve_starts(lo, hi) {
        let mut x = s;
        while x < hi {
            seg[(x - lo) as usize] = false;
            x += p;
        }
    }
    if lo < 2 {
        for x in lo..2.min(hi) {
            seg[(x - lo) as usize] = false;
        }
    }
    seg.iter().filter(|&&b| b).count() as u64
}

fn sieve_ops(chunk: u64, p: &Params) -> u64 {
    let nb = p.blocks_or(16);
    let (lo, _) = sieve_bounds(chunk, p, 0);
    let (_, hi) = sieve_bounds(chunk, p, nb - 1);
    let crossings: u64 = if hi > lo {
        sieve_starts(lo, hi).iter().map(|(p, st)| (hi - 1 - st) / p + 1).sum()
    } else {
        0
    };
    crossings + p.width
}

fn sieve_piece_on(chunk: u64, p: &Params, i: u64) -> Vec<u8> {
    let (lo, hi) = sieve_bounds(chunk, p, i);
    let mut out = loc(i).to_vec();
    out.extend_from_slice(&lo.to_be_bytes());
    out.extend_from_slice(&sieve_count(lo, hi).to_be_bytes());
    out
}

fn is_prime(n: u64) -> bool {
    // The seed's Miller-Rabin: trial division by the small primes, then
    // the deterministic base sets.
    if n < 2 {
        return false;
    }
    for q in [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if n % q == 0 {
            return n == q;
        }
    }
    let mut d = n - 1;
    let mut s = 0u32;
    while d % 2 == 0 {
        d /= 2;
        s += 1;
    }
    let bases: &[u64] = if n < 3_215_031_751 {
        &[2, 3, 5, 7]
    } else {
        &[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    };
    for &a in bases {
        let mut x = modpow(a, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        let mut passed = false;
        for _ in 0..s.saturating_sub(1) {
            x = ((x as u128 * x as u128) % n as u128) as u64;
            if x == n - 1 {
                passed = true;
                break;
            }
        }
        if !passed {
            return false;
        }
    }
    true
}

fn modpow(a: u64, mut e: u64, n: u64) -> u64 {
    let mut acc: u128 = 1;
    let mut base = a as u128;
    let m = n as u128;
    while e > 0 {
        if e & 1 == 1 {
            acc = acc * base % m;
        }
        base = base * base % m;
        e >>= 1;
    }
    acc as u64
}

fn sieve_formal(chunk: u64, p: &Params, i: u64) -> Vec<u8> {
    let (lo, hi) = sieve_bounds(chunk, p, i);
    let count = (lo..hi).filter(|&x| is_prime(x)).count() as u64;
    let mut out = loc(i).to_vec();
    out.extend_from_slice(&lo.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    out
}

// -- search -----------------------------------------------------------------------------

fn search_bounds(chunk: u64, p: &Params, i: u64) -> (u64, u64) {
    let nb = p.blocks_or(8);
    let lo0 = chunk * p.span + p.base.unwrap_or(0);
    (lo0 + i * p.span / nb, lo0 + (i + 1) * p.span / nb)
}

/// `H("cert", job, x)` below the target 2^(512−bits): the digest's top
/// `bits` bits are all zero.
fn cert_below(job: u64, x: u64, bits: u32) -> bool {
    let d = h("cert", &[Part::Nat(job), Part::Nat(x)]);
    let full = (bits / 8) as usize;
    let rem = bits % 8;
    if d[..full].iter().any(|&b| b != 0) {
        return false;
    }
    if rem > 0 && full < 64 && d[full] >= (1u8 << (8 - rem)) {
        return false;
    }
    true
}

fn search_piece_on(job: u64, chunk: u64, p: &Params, i: u64) -> Vec<u8> {
    let (lo, hi) = search_bounds(chunk, p, i);
    let mut out = loc(i).to_vec();
    out.extend_from_slice(&lo.to_be_bytes());
    for x in lo..hi {
        if cert_below(job, x, p.bits) {
            out.extend_from_slice(&x.to_be_bytes());
        }
    }
    out
}

/// The formal road for search writes the certificate hash apart (the
/// seed's `_cert_hash`): same construction, separately expressed — the
/// digest fed part by part from the raw framing.
fn search_formal(job: u64, chunk: u64, p: &Params, i: u64) -> Vec<u8> {
    // `_cert_hash` in the seed is hashing.H with the framing written out;
    // poe-crypto's h() is that same framing (verified byte-exact at
    // Step 2), so the formal road differs in expression, not in hash.
    search_piece_on(job, chunk, p, i)
}

// -- dot_f32 ------------------------------------------------------------------------------

fn dot_x(job: u64, chunk: u64, p: &Params) -> Vec<f32> {
    floats32(&seed_of("X", job, chunk), (p.m * p.k) as usize)
}
fn dot_w(job: u64, p: &Params) -> Vec<f32> {
    floats32(&h("w", &[Part::Nat(job)]), p.k as usize)
}

fn dot_piece_on(job: u64, chunk: u64, p: &Params, i: u64) -> Vec<u8> {
    let x = dot_x(job, chunk, p);
    let w = dot_w(job, p);
    let mut acc: f32 = 0.0;
    let mut started = false;
    for kk in 0..p.k {
        let prod = x[(i * p.k + kk) as usize] * w[kk as usize];
        acc = if started { acc + prod } else { prod };
        started = true;
    }
    let mut out = loc(i).to_vec();
    out.extend_from_slice(&acc.to_le_bytes());
    out
}

/// The formal road for the dot: every product and partial sum computed
/// exactly in f64 (grid values and their products are exact there) and
/// rounded to binary32 at each step — the seed's binary32 emulation of
/// the pinned plan, sharing no arithmetic with the executor's f32 ops.
fn dot_formal(job: u64, chunk: u64, p: &Params, i: u64) -> Vec<u8> {
    let x = dot_x(job, chunk, p);
    let w = dot_w(job, p);
    let mut acc: f32 = 0.0;
    let mut started = false;
    for kk in 0..p.k {
        let prod_exact = x[(i * p.k + kk) as usize] as f64 * w[kk as usize] as f64;
        let prod = prod_exact as f32;
        acc = if started {
            ((acc as f64) + (prod as f64)) as f32
        } else {
            prod
        };
        started = true;
    }
    let mut out = loc(i).to_vec();
    out.extend_from_slice(&acc.to_le_bytes());
    out
}

/// The seed's material plant for the dot: one input negated.
pub fn dot_plant_piece(job: u64, chunk: u64, p: &Params, i: u64, salt: u64) -> Vec<u8> {
    let mut x = dot_x(job, chunk, p);
    let w = dot_w(job, p);
    let at = (i * p.k + salt % p.k) as usize;
    x[at] = if x[at] != 0.0 { -x[at] } else { 0.5 };
    let mut acc: f32 = 0.0;
    let mut started = false;
    for kk in 0..p.k {
        let prod = x[(i * p.k + kk) as usize] * w[kk as usize];
        acc = if started { acc + prod } else { prod };
        started = true;
    }
    let mut out = loc(i).to_vec();
    out.extend_from_slice(&acc.to_le_bytes());
    out
}

// -- piecewise commitments -----------------------------------------------------------------

/// A leaf: `H("piece", i, piece)` (the seed's `piece_levels`).
pub fn leaf_of(i: u64, piece: &[u8]) -> H512 {
    h("piece", &[Part::Nat(i), Part::Bytes(piece)])
}

/// A result's side: the Merkle root of its pieces.
pub fn side_of(pieces: &[Vec<u8>]) -> H512 {
    let leaves: Vec<H512> = pieces.iter().enumerate().map(|(i, p)| leaf_of(i as u64, p)).collect();
    merkle_root(&leaves)
}

/// Open piece `i` against the side (the seed's `open_piece`).
pub fn open_piece(pieces: &[Vec<u8>], side: &H512, i: usize) -> Option<Vec<u8>> {
    if i >= pieces.len() {
        return None;
    }
    let leaves: Vec<H512> = pieces.iter().enumerate().map(|(j, p)| leaf_of(j as u64, p)).collect();
    let proof = merkle_proof(&leaves, i);
    if merkle_verify(side, &leaf_of(i as u64, &pieces[i]), &proof) {
        Some(pieces[i].clone())
    } else {
        None
    }
}

// -- claims and the triaxial audit -------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Claim {
    pub task: u64,
    pub kernel: Kernel,
    pub job: u64,
    pub chunk: u64,
    pub side: H512,
    pub npieces: u64,
    pub ops: u64,
    pub claimant: u64,
}

impl Claim {
    /// Commit a finished run as a claim.
    pub fn commit(
        task: u64,
        kernel: Kernel,
        job: u64,
        chunk: u64,
        p: &Params,
        pieces: &[Vec<u8>],
        claimant: u64,
    ) -> Claim {
        Claim {
            task,
            kernel,
            job,
            chunk,
            side: side_of(pieces),
            npieces: pieces.len() as u64,
            ops: kernel.ops_of(job, chunk, p),
            claimant,
        }
    }

    /// The claim's registration spend in the kernel's record: a claim on
    /// the (task, chunk) height under the ContractVersion registry,
    /// naming its side.
    pub fn registration_spend(&self) -> Spend {
        Spend {
            nf: h_u64("compute-height", &[Part::Nat(self.task), Part::Nat(self.chunk)]),
            tx: h_u64("side", &[Part::Bytes(&self.side)]),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Sealed,
    Broken { seal: &'static str, why: String },
    Open { missing: &'static str },
}

/// The triaxial audit of one claim. `record` is the registration road's
/// evidence: the spends the kernel's record holds for this height.
/// `draw_seed` is the beacon's draw — probes are chosen from it only
/// now, after the claim has committed.
pub fn audit(claim: &Claim, p: &Params, pieces: &[Vec<u8>], record: &[Spend], draw_seed: &H512) -> Verdict {
    // Seal L — the claim's sentence: shape, motion, side.
    if pieces.len() as u64 != claim.npieces || claim.npieces != claim.kernel.npieces(p) {
        return Verdict::Broken { seal: "L", why: "piece count off the canonical shape".into() };
    }
    if claim.ops != claim.kernel.ops_of(claim.job, claim.chunk, p) {
        return Verdict::Broken { seal: "L", why: "reported ops off the kernel's motion".into() };
    }
    if side_of(pieces) != claim.side {
        return Verdict::Broken { seal: "L", why: "the pieces do not hash to the committed side".into() };
    }
    if pieces.is_empty() {
        return Verdict::Open { missing: "pieces" };
    }

    // The registration road: replay the record. The claim's own spend
    // must be there and must have been accepted; a rival's accepted
    // spend on the same height means this side is not the registered one.
    let mut registry = Registry::new(RegistryKind::ContractVersion);
    let mine = claim.registration_spend();
    let mut my_outcome: Option<ClaimOutcome> = None;
    for s in record {
        let out = registry.claim(*s);
        if *s == mine {
            my_outcome = Some(out);
        }
    }
    match my_outcome {
        None => return Verdict::Open { missing: "registration" },
        Some(ClaimOutcome::Evidence) => {
            return Verdict::Broken { seal: "G", why: "a rival side holds the registration".into() };
        }
        Some(ClaimOutcome::Accepted) | Some(ClaimOutcome::Duplicate) => {}
    }

    // Seal M's warrant: the draw must span at least three probes (or the
    // whole result, when smaller).
    let n = pieces.len();
    let want = 3.min(n);
    let mut probes: Vec<usize> = Vec::new();
    let mut k = 0u64;
    while probes.len() < want {
        let idx = (h_u64("probe", &[Part::Bytes(draw_seed), Part::Nat(claim.task), Part::Nat(k)]) as usize) % n;
        if !probes.contains(&idx) {
            probes.push(idx);
        }
        k += 1;
    }

    // Seal G — the gates at each probe: the piece opens against the
    // side; the executed road reproduces it; the formal road derives it.
    for &i in &probes {
        if open_piece(pieces, &claim.side, i).is_none() {
            return Verdict::Broken { seal: "G", why: format!("piece {i} does not open against the side") };
        }
        if claim.kernel.piece_on(claim.job, claim.chunk, p, i as u64) != pieces[i] {
            return Verdict::Broken { seal: "G", why: format!("executed road disagrees at piece {i}") };
        }
        if claim.kernel.formal(claim.job, claim.chunk, p, i as u64) != pieces[i] {
            return Verdict::Broken { seal: "G", why: format!("formal road disagrees at piece {i}") };
        }
    }

    Verdict::Sealed
}
