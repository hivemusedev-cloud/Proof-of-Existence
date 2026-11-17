//! The local control surface — PoE OS device build, Phase 0
//! item 3 (2026-11-16).
//!
//! The adopted OS model needs the suite's functions — Ledger
//! Keeper, Wallet, Bridge, Swap, Node — reachable by a local
//! app shell, and it forbids a network API on the node. This
//! module is that surface: a **Unix-domain socket** in the
//! node's data directory (`control.sock`, mode 0600), speaking
//! one JSON object per line in each direction. Nothing here
//! listens on a network interface; the only clients are
//! processes running as the same user on the same machine —
//! the same trust boundary as the node's key files. (On
//! non-Unix platforms the surface does not start yet; a
//! named-pipe backend is Phase 1 work, stated as such.)
//!
//! What is wired, honestly:
//!
//! * `status` — the node's own snapshot (machine, key backend,
//!   epoch, apply head, minted, queued op count), refreshed by
//!   the round loop after every finalized round is applied.
//! * The **wallet** (poe-wallet): `wallet.notes` lists this
//!   machine's live notes from the ledger snapshot;
//!   `wallet.containers` / `wallet.container.import` manage the
//!   Existence Containers held in `<dir>/wallet/`;
//!   `wallet.show` performs an offline show of a held container
//!   and records it in the container's log — the wallet's real
//!   verbs, end to end. The surface never returns a container's
//!   line secret or its raw bytes; a show is what crosses, as
//!   the protocol intends.
//! * **Transfers**: `wallet.transfer` takes a complete kernel
//!   transfer (full note marks in and out — the ledger's notes
//!   are bearer instruments, and no note-addressing convention
//!   exists yet to invent friendlier parameters), pre-validates
//!   it with `Ledger::accepts`, and queues it. The proposer's
//!   op list drains the queue each round, re-validating against
//!   the live ledger; a stale op is dropped with a log line,
//!   never forced into a block.
//! * **Bridge / Swap** (poe-v2): the genesis curve lives in the
//!   node process; `v2.state` and `v2.quote` answer from its
//!   real math. Execution (`v2.swap`, `v2.bridge`) is refused
//!   with a `gated` error: the V2 gate is closed by the owners'
//!   rule (2026-11-17) until the Stage 2 soak criteria are met
//!   on a real mesh and reported. The lanes light up when the
//!   gate opens, not before.
//! * **Finality certificates** (light-duty addition #1):
//!   `cert.latest` summarizes the newest epoch certificate the
//!   node has emitted, and `cert.fetch` returns one epoch's
//!   certificate in full (hex of its canonical encoding) — the
//!   portable finality evidence a light client verifies from
//!   scratch (see poe-finality's `cert` module). Certificates
//!   are emitted at epoch closes and reloaded from
//!   `<dir>/certs/` at startup.
//!
//! JSON is handled by a small in-module parser/serializer: the
//! surface's payloads are flat, and the workspace's discipline
//! is hand-rolled formats over new dependencies.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use poe_kernel::ledger::{Ledger, Note, Op};
use poe_v2::Curve;
use poe_wallet::Container;

/// The AskAdmin carrying the Stage 4 decisions that gate V2
/// execution; named in the gated error so an operator can find
/// the pending decision from the refusal alone.
pub const V2_GATE_QUESTION: &str = "q-b50bcedac227dd454d70955bcd5acdfc";

/// State shared between the node loop (writer of snapshots,
/// drainer of the op queue) and the control thread (reader,
/// queue producer). One lock, short holds: control traffic is
/// a trickle next to the round loop.
pub struct ControlShared {
    pub machine: u64,
    pub backend: &'static str,
    pub joined: bool,
    pub epoch: u64,
    pub next_apply: u64,
    pub head_round: Option<u64>,
    pub minted: u64,
    /// This machine's note marks: `(cm, nf)` derived from its
    /// device public key at join. Grant notes are stamped with
    /// the registration's marks, so these two numbers are how
    /// the wallet finds its own notes in the ledger.
    pub my_marks: (u64, u64),
    /// Live (spendable) notes bearing `my_marks`, refreshed by
    /// the node after each apply.
    pub my_notes: Vec<Note>,
    /// A ledger snapshot for `accepts` pre-validation of
    /// queued ops. Refreshed with `my_notes`.
    pub ledger: Ledger,
    /// Ops queued through the surface, drained by the proposer.
    pub pending: Vec<Op>,
    /// Where Existence Containers live: `<node dir>/wallet/`.
    pub wallet_dir: PathBuf,
    /// The V2 genesis curve, for state and quotes.
    pub curve: Curve,
    /// Finality certificates this node has emitted, by epoch
    /// (light-duty addition #1). Filled at epoch closes and
    /// reloaded from `<dir>/certs/` at startup.
    pub certs: BTreeMap<u64, poe_finality::Certificate>,
    /// The most recent close's companion state (addition #2):
    /// (epoch, Merkle companion root, the ledger as that close
    /// left it), so `note.proof` serves paths against exactly
    /// the root the epoch's certificate names. Set at closes;
    /// empty until this process has closed an epoch.
    pub close_companion: Option<(u64, poe_crypto::hash::H512, Ledger)>,
}

pub type Shared = Arc<RwLock<ControlShared>>;

impl ControlShared {
    pub fn new(machine: u64, backend: &'static str, my_marks: (u64, u64), wallet_dir: PathBuf) -> Shared {
        Arc::new(RwLock::new(ControlShared {
            machine,
            backend,
            joined: false,
            epoch: 0,
            next_apply: 0,
            head_round: None,
            minted: 0,
            my_marks,
            my_notes: Vec::new(),
            ledger: Ledger::genesis(),
            pending: Vec::new(),
            wallet_dir,
            curve: poe_v2::genesis_curve(),
            certs: BTreeMap::new(),
            close_companion: None,
        }))
    }

    /// Recompute the wallet view and status fields from a
    /// ledger the node has just applied. Called by the node
    /// after startup and after every finalized batch.
    pub fn refresh(&mut self, ledger: &Ledger, next_apply: u64, head_round: Option<u64>) {
        self.epoch = ledger.now;
        self.minted = ledger.minted as u64;
        self.joined = ledger.machines.contains(&self.machine);
        self.next_apply = next_apply;
        self.head_round = head_round;
        self.my_notes = ledger
            .births
            .iter()
            .filter(|n| n.cm == self.my_marks.0 && n.nf == self.my_marks.1 && ledger.is_input_ok(n))
            .copied()
            .collect();
        self.ledger = ledger.clone();
    }
}

// -- the server ---------------------------------------------------------------

/// Start the control thread on `sock_path` (Unix domain
/// socket, mode 0600). The Windows named-pipe counterpart is
/// below; the dispatch (`handle_line`) is shared.
#[cfg(unix)]
pub fn serve(shared: Shared, sock_path: PathBuf) {
    std::thread::spawn(move || {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;
        let _ = std::fs::remove_file(&sock_path);
        let listener = match UnixListener::bind(&sock_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("CONTROL surface failed to bind {}: {e}", sock_path.display());
                return;
            }
        };
        let _ = std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600));
        println!("CONTROL listening on {} (local only)", sock_path.display());
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let Ok(mut writer) = stream.try_clone() else { continue };
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            if reader.read_line(&mut line).is_ok() && !line.trim().is_empty() {
                let response = handle_line(line.trim(), &shared);
                let _ = writer.write_all(response.as_bytes());
                let _ = writer.write_all(b"\n");
            }
        }
    });
}

/// Start the control thread on a Windows named pipe
/// (`\\.\pipe\poe-node-<dirname>`, the name
/// `appenv::control_endpoint` fixes). The pipe's default ACL
/// restricts it to the creating user, SYSTEM and admins —
/// the same local trust boundary as the Unix socket's 0600.
/// One request per connection, exactly as on Unix: a JSON
/// line in, a JSON line out.
#[cfg(windows)]
pub fn serve(shared: Shared, pipe_path: PathBuf) {
    std::thread::spawn(move || {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{
            CloseHandle, GetLastError, ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE,
        };
        use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile, PIPE_ACCESS_DUPLEX};
        use windows_sys::Win32::System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
            PIPE_TYPE_BYTE, PIPE_WAIT,
        };
        let name: Vec<u16> =
            pipe_path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        println!("CONTROL listening on {} (local only)", pipe_path.display());
        loop {
            let handle = unsafe {
                CreateNamedPipeW(
                    name.as_ptr(),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    1,
                    65_536,
                    65_536,
                    0,
                    std::ptr::null(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                eprintln!(
                    "CONTROL surface failed to create {} (error {})",
                    pipe_path.display(),
                    unsafe { GetLastError() }
                );
                return;
            }
            let connected = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) } != 0
                || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
            if connected {
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let mut read = 0u32;
                    let ok = unsafe {
                        ReadFile(
                            handle,
                            chunk.as_mut_ptr(),
                            chunk.len() as u32,
                            &mut read,
                            std::ptr::null_mut(),
                        )
                    };
                    if ok == 0 || read == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..read as usize]);
                    if buf.contains(&b'\n') {
                        break;
                    }
                }
                let line = String::from_utf8_lossy(&buf).trim().to_string();
                if !line.is_empty() {
                    let response = handle_line(&line, &shared);
                    let mut out = response.into_bytes();
                    out.push(b'\n');
                    let mut written = 0u32;
                    unsafe {
                        WriteFile(
                            handle,
                            out.as_ptr(),
                            out.len() as u32,
                            &mut written,
                            std::ptr::null_mut(),
                        );
                    }
                }
            }
            unsafe {
                DisconnectNamedPipe(handle);
                CloseHandle(handle);
            }
        }
    });
}

#[cfg(not(any(unix, windows)))]
pub fn serve(_shared: Shared, _sock_path: PathBuf) {
    eprintln!("CONTROL surface unavailable on this platform");
}

// -- request dispatch ---------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn inclusion_json(p: &poe_store::merkle::InclusionProof) -> String {
    let sibs: Vec<String> = p.siblings.iter().map(|s| format!("\"{}\"", hex(s))).collect();
    format!(
        "{{\"index\":{},\"leaf_count\":{},\"siblings\":[{}]}}",
        p.index,
        p.leaf_count,
        sibs.join(",")
    )
}

fn absence_json(p: &poe_store::merkle::AbsenceProof) -> String {
    let side = |e: &Option<(u64, poe_store::merkle::InclusionProof)>| match e {
        Some((k, pr)) => format!("{{\"key\":{},\"proof\":{}}}", k, inclusion_json(pr)),
        None => "null".to_string(),
    };
    format!(
        "{{\"leaf_count\":{},\"pred\":{},\"succ\":{}}}",
        p.leaf_count,
        side(&p.pred),
        side(&p.succ)
    )
}

fn ok(result: String) -> String {
    format!("{{\"ok\":true,\"result\":{result}}}")
}

fn err(code: &str, message: &str) -> String {
    format!(
        "{{\"ok\":false,\"error\":{{\"code\":\"{}\",\"message\":\"{}\"}}}}",
        esc(code),
        esc(message)
    )
}

/// Handle one request line. Pure over the shared state, so the
/// whole surface is testable without a socket or a node.
pub fn handle_line(line: &str, shared: &Shared) -> String {
    let req = match parse(line) {
        Ok(j) => j,
        Err(e) => return err("bad_json", &e),
    };
    let method = match req.get("method").and_then(Json::as_str) {
        Some(m) => m.to_string(),
        None => return err("bad_request", "a request needs a \"method\" string"),
    };
    let params = req.get("params").cloned().unwrap_or(Json::Null);
    match method.as_str() {
        "status" => {
            let s = shared.read().expect("control lock");
            ok(format!(
                "{{\"machine\":{},\"keys_backend\":\"{}\",\"joined\":{},\"epoch\":{},\"next_apply\":{},\"head_round\":{},\"minted\":{},\"pending_ops\":{},\"containers\":{},\"v2_gate\":\"closed\"}}",
                s.machine,
                esc(s.backend),
                s.joined,
                s.epoch,
                s.next_apply,
                s.head_round.map(|r| r.to_string()).unwrap_or_else(|| "null".into()),
                s.minted,
                s.pending.len(),
                count_containers(&s.wallet_dir),
            ))
        }
        "wallet.notes" => {
            let s = shared.read().expect("control lock");
            let total: u128 = s.my_notes.iter().map(|n| n.value as u128).sum();
            let notes: Vec<String> = s.my_notes.iter().map(note_json).collect();
            ok(format!("{{\"total\":{},\"notes\":[{}]}}", total, notes.join(",")))
        }
        "wallet.containers" => {
            let s = shared.read().expect("control lock");
            match list_containers(&s.wallet_dir) {
                Ok(list) => {
                    let items: Vec<String> = list.iter().map(container_json).collect();
                    ok(format!("{{\"containers\":[{}]}}", items.join(",")))
                }
                Err(e) => err("wallet", &e),
            }
        }
        "wallet.container.import" => {
            let Some(path) = params.get("path").and_then(Json::as_str) else {
                return err("bad_request", "wallet.container.import needs a \"path\" string");
            };
            let s = shared.read().expect("control lock");
            match import_container(&s.wallet_dir, path) {
                Ok(c) => ok(container_json(&c)),
                Err(e) => err("wallet", &e),
            }
        }
        "wallet.show" => {
            let (Some(coin), Some(challenge)) = (
                params.get("coin").and_then(Json::as_u64),
                params.get("challenge").and_then(Json::as_u64),
            ) else {
                return err("bad_request", "wallet.show needs \"coin\" and \"challenge\" numbers");
            };
            let counterparty = params.get("counterparty").and_then(Json::as_u64).unwrap_or(0);
            let s = shared.read().expect("control lock");
            match wallet_show(&s.wallet_dir, coin, challenge, counterparty) {
                Ok(show) => ok(format!(
                    "{{\"coin\":{},\"challenge\":{},\"response\":{}}}",
                    show.coin, show.challenge, show.response
                )),
                Err(e) => err("wallet", &e),
            }
        }
        "wallet.transfer" => {
            let (Some(ins), Some(outs)) = (params.get("ins"), params.get("outs")) else {
                return err("bad_request", "wallet.transfer needs \"ins\" and \"outs\" note arrays");
            };
            let (Ok(ins), Ok(outs)) = (parse_notes(ins), parse_notes(outs)) else {
                return err("bad_request", "notes are {\"cm\",\"nf\",\"asset\",\"value\",\"born\"} number objects");
            };
            let op = Op::Transfer { ins, outs };
            let mut s = shared.write().expect("control lock");
            if !s.ledger.accepts(&op) {
                return err("invalid_op", "the transfer does not validate against the current ledger (Ledger::accepts is false)");
            }
            s.pending.push(op);
            ok(format!("{{\"queued\":true,\"pending_ops\":{}}}", s.pending.len()))
        }
        "v2.state" => {
            let s = shared.read().expect("control lock");
            let p = s.curve.pool();
            ok(format!(
                "{{\"spot\":{},\"pool_x\":{},\"pool_y\":{},\"curve_version\":{},\"gate\":\"closed\",\"gate_question\":\"{}\"}}",
                s.curve.spot(),
                p.x,
                p.y,
                s.curve.version,
                V2_GATE_QUESTION
            ))
        }
        "v2.quote" => {
            let (Some(side), Some(amount)) = (
                params.get("side").and_then(Json::as_str),
                params.get("amount").and_then(Json::as_str),
            ) else {
                return err("bad_request", "v2.quote needs \"side\" (buy|sell) and \"amount\" (a u128 string)");
            };
            let Ok(amount) = amount.parse::<u128>() else {
                return err("bad_request", "\"amount\" must be a u128 decimal string");
            };
            let s = shared.read().expect("control lock");
            let out = match side {
                "buy" => s.curve.buy_out(amount),
                "sell" => s.curve.sell_out(amount),
                _ => return err("bad_request", "\"side\" must be \"buy\" or \"sell\""),
            };
            ok(format!("{{\"side\":\"{}\",\"in\":{},\"out\":{}}}", esc(side), amount, out))
        }
        "cert.latest" => {
            let s = shared.read().expect("control lock");
            match s.certs.values().next_back() {
                Some(c) => ok(format!(
                    "{{\\\"epoch\\\":{},\\\"close_round\\\":{},\\\"close_block\\\":\\\"{}\\\",\\\"state_root\\\":\\\"{}\\\",\\\"companion_root\\\":\\\"{}\\\",\\\"minted\\\":{},\\\"votes\\\":{}}}",
                    c.epoch,
                    c.close_round,
                    hex(&c.close_block),
                    hex(&c.state_root),
                    hex(&c.companion_root),
                    c.minted,
                    c.votes.len(),
                )),
                None => err("no_certificate", "this node has not emitted a certificate yet"),
            }
        }
        "cert.fetch" => {
            let Some(epoch) = params.get("epoch").and_then(Json::as_u64) else {
                return err("bad_request", "cert.fetch needs an \\\"epoch\\\" number");
            };
            let s = shared.read().expect("control lock");
            match s.certs.get(&epoch) {
                Some(c) => ok(format!(
                    "{{\\\"epoch\\\":{},\\\"cert\\\":\\\"{}\\\"}}",
                    epoch,
                    hex(&poe_finality::cert::encode_certificate(c)),
                )),
                None => err("no_certificate", &format!("no certificate for epoch {epoch}")),
            }
        }
        "note.proof" => {
            let Some(cm) = params.get("cm").and_then(Json::as_u64) else {
                return err("bad_request", "note.proof needs a \\\"cm\\\" number");
            };
            let s = shared.read().expect("control lock");
            let Some((epoch, companion, ledger)) = &s.close_companion else {
                return err(
                    "no_close",
                    "this node has not closed an epoch in this run; note proofs are served from the last close",
                );
            };
            match poe_store::merkle::prove_note(ledger, cm) {
                Some(p) => ok(format!(
                    "{{\\\"epoch\\\":{},\\\"companion_root\\\":\\\"{}\\\",\\\"note\\\":{{\\\"cm\\\":{},\\\"nf\\\":{},\\\"asset\\\":{},\\\"value\\\":{},\\\"born\\\":{}}},\\\"births_root\\\":\\\"{}\\\",\\\"deaths_root\\\":\\\"{}\\\",\\\"machines_root\\\":\\\"{}\\\",\\\"births\\\":{},\\\"deaths\\\":{}}}",
                    epoch,
                    hex(companion),
                    p.note.cm,
                    p.note.nf,
                    p.note.asset,
                    p.note.value,
                    p.note.born,
                    hex(&p.births_root),
                    hex(&p.deaths_root),
                    hex(&p.machines_root),
                    inclusion_json(&p.births),
                    absence_json(&p.deaths),
                )),
                None => err(
                    "not_live",
                    &format!("no live note with cm {cm} at the close of epoch {epoch}"),
                ),
            }
        }
        "v2.swap" | "v2.bridge" => err(
            "gated",
            &format!(
                "V2 execution is gated: the gate opens only when the Stage 2 soak criteria are met on a real mesh and reported (owners' rule, 2026-11-17; the question it waited on was AskAdmin {V2_GATE_QUESTION}, since decided). Quotes are live; the lanes are not."
            ),
        ),
        _ => err("unknown_method", &format!("no such method: {method}")),
    }
}

// -- wallet storage -----------------------------------------------------------

fn container_path(wallet_dir: &std::path::Path, coin: u64) -> PathBuf {
    wallet_dir.join(format!("{coin}.poec"))
}

fn count_containers(wallet_dir: &std::path::Path) -> usize {
    list_containers(wallet_dir).map(|l| l.len()).unwrap_or(0)
}

fn list_containers(wallet_dir: &std::path::Path) -> Result<Vec<Container>, String> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(wallet_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(format!("wallet dir: {e}")),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|x| x == "poec") {
            let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
            out.push(Container::from_bytes(&bytes)?);
        }
    }
    out.sort_by_key(|c| c.coin);
    Ok(out)
}

fn load_container(wallet_dir: &std::path::Path, coin: u64) -> Result<Container, String> {
    let path = container_path(wallet_dir, coin);
    let bytes = std::fs::read(&path).map_err(|_| format!("no container held for coin {coin}"))?;
    Container::from_bytes(&bytes)
}

fn import_container(wallet_dir: &std::path::Path, source: &str) -> Result<Container, String> {
    let bytes = std::fs::read(source).map_err(|e| format!("read {source}: {e}"))?;
    let container = Container::from_bytes(&bytes)?;
    std::fs::create_dir_all(wallet_dir).map_err(|e| format!("wallet dir: {e}"))?;
    let dest = container_path(wallet_dir, container.coin);
    if dest.exists() {
        return Err(format!(
            "a container for coin {} is already held; refusing to overwrite its show log",
            container.coin
        ));
    }
    std::fs::write(&dest, container.to_bytes()).map_err(|e| format!("write container: {e}"))?;
    Ok(container)
}

fn wallet_show(
    wallet_dir: &std::path::Path,
    coin: u64,
    challenge: u64,
    counterparty: u64,
) -> Result<poe_wallet::Show, String> {
    let mut container = load_container(wallet_dir, coin)?;
    let show = poe_wallet::show(&container.line, coin, challenge);
    container.record_show(&show, counterparty)?;
    std::fs::write(container_path(wallet_dir, coin), container.to_bytes())
        .map_err(|e| format!("persist container: {e}"))?;
    Ok(show)
}

// -- JSON (minimal, in-module) ------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Num(u64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.get(key),
            _ => None,
        }
    }
    fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Num(n) => Some(*n),
            _ => None,
        }
    }
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn note_json(n: &Note) -> String {
    format!(
        "{{\"cm\":{},\"nf\":{},\"asset\":{},\"value\":{},\"born\":{}}}",
        n.cm, n.nf, n.asset, n.value, n.born
    )
}

fn container_json(c: &Container) -> String {
    format!(
        "{{\"coin\":{},\"nf\":{},\"asset\":{},\"value\":{},\"born\":{},\"owner\":{},\"shows_recorded\":{}}}",
        c.coin,
        c.nf,
        c.asset,
        c.value,
        c.born,
        c.owner,
        c.shows.len()
    )
}

fn parse_notes(j: &Json) -> Result<Vec<Note>, ()> {
    let Json::Arr(items) = j else { return Err(()) };
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        let (Some(cm), Some(nf), Some(asset), Some(value), Some(born)) = (
            it.get("cm").and_then(Json::as_u64),
            it.get("nf").and_then(Json::as_u64),
            it.get("asset").and_then(Json::as_u64),
            it.get("value").and_then(Json::as_u64),
            it.get("born").and_then(Json::as_u64),
        ) else {
            return Err(());
        };
        out.push(Note { cm, nf, asset, value, born });
    }
    Ok(out)
}

fn parse(text: &str) -> Result<Json, String> {
    let mut p = Parser { bytes: text.as_bytes(), at: 0 };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.at != p.bytes.len() {
        return Err("trailing characters after the JSON value".into());
    }
    Ok(v)
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.at < self.bytes.len() && (self.bytes[self.at] as char).is_whitespace() {
            self.at += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }
    fn value(&mut self) -> Result<Json, String> {
        match self.peek() {
            Some(b'{') => {
                self.at += 1;
                let mut map = BTreeMap::new();
                self.ws();
                if self.peek() == Some(b'}') {
                    self.at += 1;
                    return Ok(Json::Obj(map));
                }
                loop {
                    self.ws();
                    let key = match self.value()? {
                        Json::Str(s) => s,
                        _ => return Err("object keys must be strings".into()),
                    };
                    self.ws();
                    if self.peek() != Some(b':') {
                        return Err("expected ':' in object".into());
                    }
                    self.at += 1;
                    self.ws();
                    let val = self.value()?;
                    map.insert(key, val);
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.at += 1,
                        Some(b'}') => {
                            self.at += 1;
                            return Ok(Json::Obj(map));
                        }
                        _ => return Err("expected ',' or '}' in object".into()),
                    }
                }
            }
            Some(b'[') => {
                self.at += 1;
                let mut items = Vec::new();
                self.ws();
                if self.peek() == Some(b']') {
                    self.at += 1;
                    return Ok(Json::Arr(items));
                }
                loop {
                    self.ws();
                    items.push(self.value()?);
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.at += 1,
                        Some(b']') => {
                            self.at += 1;
                            return Ok(Json::Arr(items));
                        }
                        _ => return Err("expected ',' or ']' in array".into()),
                    }
                }
            }
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') => {
                self.lit("true")?;
                Ok(Json::Bool(true))
            }
            Some(b'f') => {
                self.lit("false")?;
                Ok(Json::Bool(false))
            }
            Some(b'n') => {
                self.lit("null")?;
                Ok(Json::Null)
            }
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            _ => Err("unexpected character in JSON".into()),
        }
    }
    fn lit(&mut self, word: &str) -> Result<(), String> {
        if self.bytes[self.at..].starts_with(word.as_bytes()) {
            self.at += word.len();
            Ok(())
        } else {
            Err(format!("bad literal, expected {word}"))
        }
    }
    fn number(&mut self) -> Result<Json, String> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.at += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at]).map_err(|_| "bad number")?;
        // The surface's numbers are u64 quantities; a sign or a
        // fraction has no meaning in any request and is refused
        // rather than rounded.
        text.parse::<u64>().map(Json::Num).map_err(|_| format!("number out of range or not a u64: {text}"))
    }
    fn string(&mut self) -> Result<String, String> {
        if self.peek() != Some(b'"') {
            return Err("expected a string".into());
        }
        self.at += 1;
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or("unterminated string")?;
            self.at += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = self.peek().ok_or("unterminated escape")?;
                    self.at += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'u' => {
                            let hex = self.bytes.get(self.at..self.at + 4).ok_or("bad \\u escape")?;
                            let hex = std::str::from_utf8(hex).map_err(|_| "bad \\u escape")?;
                            let cp = u32::from_str_radix(hex, 16).map_err(|_| "bad \\u escape")?;
                            self.at += 4;
                            out.push(char::from_u32(cp).ok_or("bad \\u codepoint")?);
                        }
                        _ => return Err("bad escape".into()),
                    }
                }
                _ => {
                    // Reassemble the UTF-8 the byte came from.
                    let mut buf = [0u8; 4];
                    let ch = std::str::from_utf8(&self.bytes[self.at - 1..])
                        .ok()
                        .and_then(|s| s.chars().next())
                        .ok_or("invalid UTF-8 in string")?;
                    self.at += ch.len_utf8() - 1;
                    out.push_str(ch.encode_utf8(&mut buf));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use poe_kernel::COIN;

    fn fixture(tag: &str) -> (Shared, PathBuf) {
        // Unique per test: the suite runs tests in parallel, and
        // a shared directory lets one test's cleanup delete
        // another's wallet mid-flight.
        let dir = std::env::temp_dir().join(format!("poe-control-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let wallet_dir = dir.join("wallet");
        (ControlShared::new(7, "file (software stub)", (111, 222), wallet_dir), dir)
    }

    fn call(shared: &Shared, line: &str) -> String {
        handle_line(line, shared)
    }

    #[test]
    fn status_and_v2_quote_answer_from_real_state() {
        let (shared, dir) = fixture("status");
        let status = call(&shared, r#"{"method":"status"}"#);
        assert!(status.contains("\"machine\":7"), "{status}");
        assert!(status.contains("\"v2_gate\":\"closed\""), "{status}");
        // A quote through the surface equals the curve's own math.
        let expect = poe_v2::genesis_curve().buy_out(1_000_000_000_000_000_000);
        let quote = call(&shared, r#"{"method":"v2.quote","params":{"side":"buy","amount":"1000000000000000000"}}"#);
        assert!(quote.contains(&format!("\"out\":{expect}")), "{quote}");
        // Execution is refused, gated, and names the pending decision.
        let swap = call(&shared, r#"{"method":"v2.swap","params":{}}"#);
        assert!(swap.contains("\"code\":\"gated\""), "{swap}");
        assert!(swap.contains(V2_GATE_QUESTION), "{swap}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn container_import_show_and_the_double_show_drill() {
        use poe_wallet::{extract_secret, show_consistent, LineKey};
        let (shared, dir) = fixture("drill");
        let container = Container {
            coin: 42,
            nf: 9,
            asset: COIN,
            value: 100,
            born: 0,
            owner: 7,
            line: LineKey { secret: 111, blind: 222 },
            shows: Vec::new(),
        };
        let source = dir.join("travelling.poec");
        std::fs::write(&source, container.to_bytes()).unwrap();
        let imported = call(
            &shared,
            &format!(r#"{{"method":"wallet.container.import","params":{{"path":"{}"}}}}"#, source.display()),
        );
        assert!(imported.contains("\"coin\":42"), "{imported}");
        // A second import of the same coin refuses to overwrite the log.
        let again = call(
            &shared,
            &format!(r#"{{"method":"wallet.container.import","params":{{"path":"{}"}}}}"#, source.display()),
        );
        assert!(again.contains("\"ok\":false"), "{again}");
        // Two shows at two challenges, through the surface...
        let s1 = call(&shared, r#"{"method":"wallet.show","params":{"coin":42,"challenge":5,"counterparty":77}}"#);
        let s2 = call(&shared, r#"{"method":"wallet.show","params":{"coin":42,"challenge":9,"counterparty":78}}"#);
        assert!(s1.contains("\"response\":"), "{s1}");
        // ...verify against the line equation, and extract the secret:
        // the offline double-show drill, end to end over the surface.
        let parse_resp = |s: &str| -> u64 {
            let j = parse(s).unwrap();
            j.get("result").and_then(|r| r.get("response")).and_then(Json::as_u64).unwrap()
        };
        let sh1 = poe_wallet::Show { coin: 42, challenge: 5, response: parse_resp(&s1) };
        let sh2 = poe_wallet::Show { coin: 42, challenge: 9, response: parse_resp(&s2) };
        assert!(show_consistent(111, 222, &sh1));
        assert_eq!(extract_secret(&sh1, &sh2), Some(111));
        // The shows were recorded in the held container's log.
        let list = call(&shared, r#"{"method":"wallet.containers"}"#);
        assert!(list.contains("\"shows_recorded\":2"), "{list}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn transfer_queue_validates_against_the_ledger() {
        let (shared, dir) = fixture("transfer");
        // Fixture ledger: machine 7 joins with the fixture marks,
        // a tick births its grant, the grant is then spendable.
        let grant = Note { cm: 111, nf: 222, asset: COIN, value: 1, born: 0 };
        let mut ledger = Ledger::genesis();
        ledger = ledger.act(&Op::Join { machine: 7, operator: 7, note: grant });
        ledger = ledger.act(&Op::Tick { cap: 500 });
        {
            let mut s = shared.write().unwrap();
            s.refresh(&ledger, 0, None);
        }
        let notes = call(&shared, r#"{"method":"wallet.notes"}"#);
        assert!(notes.contains("\"total\":500"), "{notes}");
        // A conserving transfer of the grant note queues. The
        // request is built from the note exactly as the ledger
        // holds it — full marks, as the surface's contract states.
        let note = {
            let s = shared.read().unwrap();
            s.my_notes.first().copied().expect("the grant note is in the wallet view")
        };
        let good = format!(
            r#"{{"method":"wallet.transfer","params":{{"ins":[{}],"outs":[{{"cm":333,"nf":444,"asset":{},"value":{},"born":0}}]}}}}"#,
            note_json(&note),
            note.asset,
            note.value
        );
        let queued = call(&shared, &good);
        assert!(queued.contains("\"queued\":true"), "{queued}");
        // A non-conserving transfer is refused at the surface.
        let bad = good.replace(
            &format!("\"value\":{},\"born\":0", note.value),
            &format!("\"value\":{},\"born\":0", note.value - 1),
        );
        let refused = call(&shared, &bad);
        assert!(refused.contains("\"code\":\"invalid_op\""), "{refused}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
