//! poe-node: the node binary.
//!
//! `poe-node` (or `poe-node demo`) runs the increment-1 kernel demo:
//! genesis -> join a machine -> close the epoch (grant is born) -> spend
//! the grant -> try to spend it again and watch the ledger refuse.
//!
//! `poe-node devnet [dir]` runs the Step-12 single-node devnet: genesis
//! built from its frozen spec, attested devices bound, a week of acts
//! persisted through poe-store, a close, a restart, and a replay check.

mod genesis;
mod testnet;

use poe_kernel::ledger::{live_a, Ledger, Note, Op};
use poe_kernel::COIN;

fn note(cm: u64, nf: u64, value: u64, born: u64) -> Note {
    Note { cm, nf, asset: COIN, value, born }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "testnet-genesis-hash" {
        // Print the genesis hash for a candidate root public key (hex):
        // the value a chain spec must carry for that root.
        let pk = testnet::hex_decode(&args[2]).expect("root pk hex");
        let spec = testnet::Spec {
            name: "poe-testnet-1".to_string(),
            root_id: 1,
            root_quota: 100_000,
            root_pk: pk,
            rounds_per_epoch: 16,
            round_secs: 3,
            ghostdag_k: 3,
            t0_unix: 0,
            genesis_hash: [0u8; 64],
        };
        let bundle = genesis::build_genesis(&spec.genesis_spec());
        println!("{}", testnet::hex_encode(&bundle.hash));
        return;
    }
    if args.len() > 1 && args[1] == "testnet-root-keygen" {
        let dir = args
            .get(2)
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        match testnet::root_keygen(&dir) {
            Ok(pk_hex) => println!("root_pk={pk_hex}"),
            Err(e) => {
                eprintln!("root keygen failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.len() > 1 && args[1] == "testnet" {
        let mut dir = std::env::temp_dir().join("poe-testnet-node");
        let mut listen = "/ip4/0.0.0.0/tcp/41001".to_string();
        let mut peers: Vec<String> = Vec::new();
        let mut sync_from: Option<std::path::PathBuf> = None;
        let mut rounds: u64 = 0;
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--dir" => {
                    dir = std::path::PathBuf::from(&args[i + 1]);
                    i += 2;
                }
                "--listen" => {
                    listen = args[i + 1].clone();
                    i += 2;
                }
                "--peer" => {
                    peers.push(args[i + 1].clone());
                    i += 2;
                }
                "--sync-from" => {
                    sync_from = Some(std::path::PathBuf::from(&args[i + 1]));
                    i += 2;
                }
                "--rounds" => {
                    rounds = args[i + 1].parse().unwrap_or(0);
                    i += 2;
                }
                other => {
                    eprintln!("unknown testnet argument: {other}");
                    std::process::exit(2);
                }
            }
        }
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let targs = testnet::TestnetArgs { dir, listen, peers, sync_from, run_rounds: rounds };
        match rt.block_on(testnet::run_testnet(targs)) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("testnet node failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.len() > 1 && args[1] == "devnet" {
        let dir = args
            .get(2)
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("poe-devnet"));
        match genesis::run_devnet(&dir) {
            Ok(lines) => {
                for l in lines {
                    println!("{l}");
                }
            }
            Err(e) => {
                eprintln!("devnet failed: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    let genesis = Ledger::genesis();
    println!("genesis: epoch {}, live coin {}, minted {}", genesis.now, live_a(&genesis, COIN), genesis.minted);

    let l1 = genesis.act(&Op::Join { machine: 7, operator: 7, note: note(1001, 2001, 0, 0) });
    println!("join machine 7: machines {:?}", l1.machines);

    let l2 = l1.act(&Op::Tick { cap: u64::MAX });
    let grant_note = l2.births[0];
    println!(
        "close -> epoch {}: grant note born, value {}, minted {}",
        l2.now, grant_note.value, l2.minted
    );

    let out = note(3001, 4001, grant_note.value, 1);
    let l3 = l2.act(&Op::Transfer { ins: vec![grant_note], outs: vec![out] });
    println!("spend grant: deaths {:?}, live coin {}", l3.deaths, live_a(&l3, COIN));

    let l4 = l3.act(&Op::Transfer { ins: vec![grant_note], outs: vec![note(3002, 4002, 1, 1)] });
    if l4 == l3 {
        println!("double spend of the same note: REFUSED (ledger unchanged)");
    } else {
        println!("ERROR: double spend was accepted");
        std::process::exit(1);
    }
}
