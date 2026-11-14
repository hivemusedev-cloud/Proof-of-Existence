# poe-zk benchmarks — Step 5 residue (partial)

Measured 2026-11-14 on the build VM (AMD EPYC 9D25, shared vCPU,
release build) with `cargo run --release -p poe-zk --example
bench_binding`. Medians of 3–7 prove runs and 15–25 verify runs per
line; two separate runs reproduced every line within ~1 ms.

| Binding | Items | Prove (median) | Verify (median) |
|---|---|---|---|
| JoinAdmission | 5 | 26 ms | 2.9 ms |
| ContractVersionExec | 5 | 187 ms | 2.9 ms |
| ContractVersionExec | 100 | 25 ms | 5.9 ms |
| ContractVersionExec | 1000 | 38 ms | 8.8 ms |

Reading these numbers honestly:

- **This is not a phone benchmark.** No phone or ARM board was
  available to the build environment. The figures say the proving
  workload is small on a desktop-class core — even the slowest
  observed prove is under 0.2 s and verification under 10 ms, so a
  phone-class core (typically several times slower) would still be
  expected to prove in at most a few seconds. That expectation is
  an extrapolation, not a measurement; on-device benchmarks remain
  owed and stay on the residue list until run on real hardware.
- The 5-item ContractVersionExec prove (187 ms) being slower than
  the 100-item prove (25 ms) is reproducible, not noise: the
  proving config seeds its RNGs deterministically, so the FRI
  proof-of-work grind (16 bits) takes a fixed, input-dependent
  number of attempts — long for this particular test vector, short
  for the others. Across varied real inputs the grind is a
  geometric random variable around the same mean; budget for the
  tail, not the median.
- Verify cost grows slowly with item count (more FRI queries over
  a larger trace): ~3 ms at 8 trace rows to ~9 ms at 1024 rows.

Still owed for Step 5 (unchanged, recorded in the repo README):
an external security review of this component, on-device (phone)
benchmarks, and binding the proved fold to the node's accumulator
hash H — the last is a deliberate, separate change: the STARK
proves the arithmetic fold in `fold_acc`, and the node's records
must adopt exactly that fold (or the AIR must constrain H itself)
before `pis[1]` can be checked against the node's own accumulator.
It touches seed-pinned arithmetic and is not a drive-by edit.
