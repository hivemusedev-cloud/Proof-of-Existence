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

use poe_kernel::ledger::{live_a, Ledger, Note, Op};
use poe_kernel::COIN;

fn note(cm: u64, nf: u64, value: u64, born: u64) -> Note {
    Note { cm, nf, asset: COIN, value, born }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
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
