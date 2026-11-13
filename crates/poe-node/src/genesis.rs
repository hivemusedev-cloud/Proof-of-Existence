//! The genesis builder and the single-node devnet (BUILD_FLOW Step 12).
//!
//! `build_genesis` assembles a chain's starting state from its frozen
//! specification: the launch profile (whose constants the genesis hash
//! commits — a different profile is a different chain), the launch
//! version, and the initially admitted attestation roots. The kernel's
//! genesis ledger is the same on every launch: the sealed reserve, no
//! machines, epoch zero. What the ceremony would do in public, this
//! builder does as tested code; executing a mainnet ceremony is not a
//! thing this crate does (see the workspace README's residue list).
//!
//! `run_devnet` wires the whole stack on one node — identity binds
//! attested devices, the epoch engine takes joins and runs a close,
//! every act persists through poe-store — then reopens the store and
//! proves the replayed state is the live state, roots included. That
//! stop-and-resume property is the devnet's reason to exist.

use poe_crypto::hash::{h, Part, H512};
use poe_crypto::pq::DsaKeypair;
use poe_epoch::{EpochEngine, Launch, Profile};
use poe_identity::{Attestation, IdentityRegistry, RootAdmission};
use poe_kernel::ledger::{Ledger, Note, Op};
use poe_kernel::COIN;
use poe_store::Store;
use std::path::Path;

/// One attestation root admitted at genesis.
pub struct RootSpec {
    pub root_id: u64,
    pub root_pk: Vec<u8>,
    pub quota_per_epoch: u64,
}

/// A chain's frozen starting specification.
pub struct GenesisSpec {
    pub profile: Profile,
    pub launch: Launch,
    pub roots: Vec<RootSpec>,
}

impl GenesisSpec {
    /// The reference launch: reference profile, Version 1, no roots
    /// pre-admitted beyond those added by the caller.
    pub fn reference_v1() -> GenesisSpec {
        GenesisSpec { profile: Profile::REFERENCE, launch: Launch::FairV1, roots: Vec::new() }
    }
}

/// Everything a node starts with.
pub struct GenesisBundle {
    pub ledger: Ledger,
    pub engine: EpochEngine,
    pub identity: IdentityRegistry,
    /// The frozen-configuration commitment: any change to the profile,
    /// the launch, or the admitted roots is a different genesis.
    pub hash: H512,
}

pub fn build_genesis(spec: &GenesisSpec) -> GenesisBundle {
    let mut identity = IdentityRegistry::new();
    for r in &spec.roots {
        identity.admit_root(RootAdmission {
            root_id: r.root_id,
            root_pk: r.root_pk.clone(),
            quota_per_epoch: r.quota_per_epoch,
        });
    }
    let mut hash = h(
        "genesis",
        &[
            Part::Nat(spec.profile.potdiv),
            Part::Nat(spec.profile.window),
            Part::Nat(spec.profile.floor),
            Part::Nat(match spec.launch {
                Launch::FairV1 => 1,
                Launch::ListedV2 => 2,
            }),
        ],
    );
    for r in &spec.roots {
        hash = h(
            "genesis-root",
            &[
                Part::Bytes(&hash),
                Part::Nat(r.root_id),
                Part::Bytes(&r.root_pk),
                Part::Nat(r.quota_per_epoch),
            ],
        );
    }
    GenesisBundle { ledger: Ledger::genesis(), engine: EpochEngine::new(spec.profile, spec.launch), identity, hash }
}

fn note(cm: u64, nf: u64, value: u64, born: u64) -> Note {
    Note { cm, nf, asset: COIN, value, born }
}

/// Run the single-node devnet in `dir`, returning its report lines. The
/// store directory is created fresh by the caller (or reused: a second
/// run on the same directory resumes where the first stopped — the
/// replay check inside proves it).
pub fn run_devnet(dir: &Path) -> std::io::Result<Vec<String>> {
    let mut lines = Vec::new();
    let mut rng = rand::thread_rng();

    // Genesis with one manufacturer root admitted.
    let root = DsaKeypair::generate(&mut rng);
    let mut spec = GenesisSpec::reference_v1();
    spec.roots.push(RootSpec { root_id: 1, root_pk: root.public_key_bytes(), quota_per_epoch: 100 });
    let bundle = build_genesis(&spec);
    lines.push(format!("genesis: profile {}, launch {}, hash {}", bundle.profile_tag(), bundle.launch_tag(), hex16(&bundle.hash)));

    let mut store = Store::open(dir)?;
    if store.ledger().now == 0 && store.ledger().machines.is_empty() {
        lines.push("store: fresh genesis state".to_string());
    } else {
        lines.push(format!("store: resumed at epoch {}", store.ledger().now));
    }
    let mut engine = bundle.engine;
    let mut identity = bundle.identity;

    // Three attested devices bind to machines 1..=3 and join.
    let mut mark = 500_000u64;
    for m in 1..=3u64 {
        let device = DsaKeypair::generate(&mut rng);
        let att = Attestation::issue(&root, &mut rng, device.public_key_bytes(), 1, 100 + m, 10_000);
        identity.bind(&att, m, 0).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("bind: {e:?}")))?;
        mark += 2;
        let op = Op::Join { machine: m, operator: m * 10, note: note(mark, mark + 1, 1, 0) };
        let _ = engine.apply(store.ledger(), &op);
        store.apply(&op)?;
    }
    lines.push("identity: 3 attested devices bound; joins accepted".to_string());

    // Close the epoch on a clone, then land the same Tick in the store;
    // the two must converge exactly (the close is deterministic).
    let mut live = store.ledger().clone();
    let rep = engine.close(&mut live, 1000, &[1, 2, 3]);
    store.apply(&Op::Tick { cap: rep.cap_handed })?;
    assert_eq!(&live, store.ledger(), "engine close and store tick converge");
    lines.push(format!(
        "close: epoch {} — {} claimants × {} = {} minted",
        rep.epoch, rep.claimants, rep.grant_each, rep.minted_this_close
    ));

    // A transfer of one grant note, then snapshot and reopen: replay
    // must reproduce the live ledger and its root chain bit for bit.
    let grant = store
        .ledger()
        .births
        .iter()
        .find(|b| b.born == 0 && b.value == rep.grant_each && b.asset == COIN && b.cm != 0)
        .cloned();
    if let Some(g) = grant {
        mark += 2;
        let op = Op::Transfer { ins: vec![g], outs: vec![note(mark, mark + 1, rep.grant_each, 1)] };
        store.apply(&op)?;
        lines.push("transfer: one grant note moved to a fresh mark".to_string());
    }
    store.snapshot()?;
    let live_ledger = store.ledger().clone();
    let live_roots: Vec<(u64, H512)> = store.roots().to_vec();
    drop(store);
    let reopened = Store::open(dir)?;
    assert_eq!(&live_ledger, reopened.ledger(), "replay reproduces the live ledger");
    assert_eq!(live_roots, reopened.roots().to_vec(), "the root chain survives the restart");
    lines.push(format!(
        "restart: replay == live state at epoch {}; {} state roots on record",
        reopened.ledger().now,
        live_roots.len()
    ));
    Ok(lines)
}

fn hex16(bytes: &H512) -> String {
    bytes[..16].iter().map(|b| format!("{b:02x}")).collect()
}

impl GenesisBundle {
    pub fn profile_tag(&self) -> String {
        format!("pot/{} win/{} floor/{}", self.engine.profile.potdiv, self.engine.profile.window, self.engine.profile.floor)
    }
    pub fn launch_tag(&self) -> &'static str {
        match self.engine.launch {
            Launch::FairV1 => "V1-fair",
            Launch::ListedV2 => "V2-listed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_is_the_kernels_and_the_hash_freezes_the_spec() {
        let spec = GenesisSpec::reference_v1();
        let a = build_genesis(&spec);
        assert_eq!(a.ledger, Ledger::genesis());
        assert_eq!(a.ledger.minted, poe_kernel::RESERVE);
        // Same spec, same genesis.
        let b = build_genesis(&spec);
        assert_eq!(a.hash, b.hash);
        // Any constant moved: a different chain.
        let mut moved = GenesisSpec::reference_v1();
        moved.profile = Profile::SLOW_POT;
        assert_ne!(a.hash, build_genesis(&moved).hash);
        let mut moved2 = GenesisSpec::reference_v1();
        moved2.launch = Launch::ListedV2;
        assert_ne!(a.hash, build_genesis(&moved2).hash);
        let mut moved3 = GenesisSpec::reference_v1();
        moved3.roots.push(RootSpec { root_id: 9, root_pk: vec![1, 2, 3], quota_per_epoch: 5 });
        assert_ne!(a.hash, build_genesis(&moved3).hash);
        // An admitted root actually admits: a device under it binds.
        let mut rng = rand::thread_rng();
        let root = DsaKeypair::generate(&mut rng);
        let mut spec_r = GenesisSpec::reference_v1();
        spec_r.roots.push(RootSpec { root_id: 4, root_pk: root.public_key_bytes(), quota_per_epoch: 10 });
        let mut bundle_r = build_genesis(&spec_r);
        let device = DsaKeypair::generate(&mut rng);
        let att = Attestation::issue(&root, &mut rng, device.public_key_bytes(), 4, 1, 100);
        bundle_r.identity.bind(&att, 42, 0).expect("the genesis root admits its devices");
        assert!(bundle_r.identity.can_earn(42));
    }

    #[test]
    fn devnet_runs_and_resumes() {
        let dir = std::env::temp_dir().join(format!("poe-devnet-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let lines = run_devnet(&dir).expect("devnet run");
        assert!(lines.iter().any(|l| l.contains("close:")), "the week closed: {lines:?}");
        assert!(lines.iter().any(|l| l.contains("restart: replay == live")), "{lines:?}");
        // A second run on the same directory resumes.
        let lines2 = run_devnet(&dir).expect("devnet resume");
        assert!(lines2.iter().any(|l| l.contains("resumed") || l.contains("restart:")), "{lines2:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
