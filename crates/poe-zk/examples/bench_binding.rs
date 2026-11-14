//! Step 5 residue measurement: prove/verify timings for the binding
//! STARK on THIS machine (a shared-CPU VM — see BENCHMARKS.md in
//! this crate for the recorded numbers and their limits). These are
//! desktop-class CPU numbers, NOT phone benchmarks: no phone was
//! available to the build environment, and phone-class ARM timings
//! remain owed (recorded in the repo README's residue list).
//!
//! Run: cargo run --release -p poe-zk --example bench_binding

use poe_zk::{prove_binding, verify_binding, Binding, BindingKind};
use std::time::Instant;

fn bench(kind: BindingKind, n_items: usize, prove_iters: usize, verify_iters: usize) {
    let items: Vec<u64> = (0..n_items as u64).map(|i| 1_000_003 * i + 77).collect();
    let b = Binding { kind, items, seed: 7, check_start: 0 };
    let (proof, pis) = prove_binding(&b).expect("prove (warm-up)");

    let mut prove_ms = Vec::new();
    for _ in 0..prove_iters {
        let t = Instant::now();
        let _ = prove_binding(&b).expect("prove");
        prove_ms.push(t.elapsed().as_secs_f64() * 1e3);
    }
    let mut verify_ms = Vec::new();
    for _ in 0..verify_iters {
        let t = Instant::now();
        verify_binding(kind, &proof, &pis).expect("verify");
        verify_ms.push(t.elapsed().as_secs_f64() * 1e3);
    }
    prove_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    verify_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let med = |v: &Vec<f64>| v[v.len() / 2];
    println!(
        "kind={kind:?} items={n_items}: prove median {:.1} ms (min {:.1}), verify median {:.2} ms (min {:.2})",
        med(&prove_ms),
        prove_ms[0],
        med(&verify_ms),
        verify_ms[0]
    );
}

fn main() {
    println!("poe-zk binding STARK benchmark (release build, this machine only)");
    bench(BindingKind::JoinAdmission, 5, 7, 25);
    bench(BindingKind::ContractVersionExec, 5, 7, 25);
    bench(BindingKind::ContractVersionExec, 100, 5, 25);
    bench(BindingKind::ContractVersionExec, 1000, 3, 15);
}
