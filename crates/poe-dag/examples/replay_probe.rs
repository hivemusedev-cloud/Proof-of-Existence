//! Shaped-replay probe: builds a testnet-shaped DAG (fixed width per
//! round, parents from the previous round's tips) in the new `Dag` and
//! in the verbatim old implementation, prints peak RSS (VmHWM) and a
//! checksum of the linearization so the two can be compared.
//!
//! Usage: replay_probe <new|old> <rounds> <width>

#[path = "../tests/old_dag.rs"]
mod old_dag;

use poe_dag::{Block, Dag};

fn peak_rss_mb() -> f64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kb: f64 = rest.trim().trim_end_matches(" kB").trim().parse().unwrap();
            return kb / 1024.0;
        }
    }
    -1.0
}

fn checksum(order: &[[u8; 64]]) -> u64 {
    // FNV-1a over the ordered ids — just a divergence tripwire.
    let mut h: u64 = 0xcbf29ce484222325;
    for id in order {
        for b in id {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
    }
    h
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("new");
    let rounds: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(600);
    let width: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(6);

    let t0 = std::time::Instant::now();
    if mode == "old" {
        let mut d = old_dag::OldDag::new(3);
        let g = old_dag::Block::new(1, 0, vec![], vec![0]);
        let gid = g.id;
        d.insert(g).unwrap();
        let mut prev: Vec<[u8; 64]> = vec![gid];
        for r in 1..rounds {
            let mut this = Vec::new();
            for m in 0..width {
                let p1 = prev[(m as usize) % prev.len()];
                let p2 = prev[((m as usize) + 1) % prev.len()];
                let mut parents = vec![p1];
                if p2 != p1 {
                    parents.push(p2);
                }
                let b = old_dag::Block::new(m + 1, r, parents, vec![(r % 251) as u8]);
                this.push(b.id);
                d.insert(b).unwrap();
            }
            prev = this;
        }
        let order = d.linearize();
        println!(
            "OLD rounds={rounds} width={width} blocks={} checksum={:016x} peak_rss={:.0} MB elapsed={:.1}s",
            order.len(),
            checksum(&order),
            peak_rss_mb(),
            t0.elapsed().as_secs_f64()
        );
    } else {
        let mut d = Dag::new(3);
        let g = Block::new(1, 0, vec![], vec![0]);
        let gid = g.id;
        d.insert(g).unwrap();
        let mut prev: Vec<[u8; 64]> = vec![gid];
        for r in 1..rounds {
            let mut this = Vec::new();
            for m in 0..width {
                let p1 = prev[(m as usize) % prev.len()];
                let p2 = prev[((m as usize) + 1) % prev.len()];
                let mut parents = vec![p1];
                if p2 != p1 {
                    parents.push(p2);
                }
                let b = Block::new(m + 1, r, parents, vec![(r % 251) as u8]);
                this.push(b.id);
                d.insert(b).unwrap();
            }
            prev = this;
        }
        let order = d.linearize();
        println!(
            "NEW rounds={rounds} width={width} blocks={} checksum={:016x} peak_rss={:.0} MB elapsed={:.1}s",
            order.len(),
            checksum(&order),
            peak_rss_mb(),
            t0.elapsed().as_secs_f64()
        );
    }
}
