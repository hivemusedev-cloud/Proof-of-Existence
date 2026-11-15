# Proof of Existence — external audit package

Prepared 2026-11-14 for an external auditor. This document is the
map: what the code is, how to build and verify it, what has already
been found (by the operator, by the public testnet, and by an
independent tester), and where the open questions live. Nothing in
this package has been audited externally yet — arranging that audit
is the owner's step; this package exists so an auditor can start
cold.

## What this is

A Rust implementation of the Proof of Existence protocol
(double-spend defined as a relation between two acts on one
height; five ledger acts — join, create, issue, transfer,
close/tick — plus the approved renewal act; GHOSTDAG ordering;
ticket-drawn committees; XMSS one-time vote signatures; ML-DSA
device identities; a Plonky3 FRI-STARK for the kernel's proof
bindings). The Lean 4 files are the specification; the Rust must
match them definition for definition. The design documents (the
Manual v2.0.0, Tokenomics v1.1.0, Compute Seed v0.3.0) are the
authors' — ask the owner for them; the repo's README states what
was built per build step and lists every known deviation.

## Build and verify

- Toolchain: Rust (rustup, stable). `cargo build --release`,
  `cargo test --release` at the workspace root. The full suite is
  the primary gate; it includes a Byzantine simnet battery and, as
  of 2026-11-14, a 100-machine scale simnet
  (`crates/poe-finality/tests/simnet_scale.rs`).
- The Lean specification compiles clean under Lean 4.19.0 with
  only standard axioms (verification report from the independent
  re-verification of 2026-11-10 is available from the owner).
- Public testnet `poe-testnet-1` is live; `testnet/TESTNET.md`
  carries its parameters, the bootstrap bundle, and the running
  operations log — read it: it records every stall, fork, and
  recovery with causes, including the findings below.

## Scope for audit (in priority order)

1. `crates/poe-kernel` — the ledger fold: the five acts plus
   renewal, validity, the global one-law registry semantics.
2. `crates/poe-finality` + `crates/poe-dag` — GHOSTDAG ordering,
   committee/proposer ticket draws, vote counting, evidence and
   revocation, finality.
3. `crates/poe-crypto` — the hash H (must stay byte-exact against
   the Compute Seed), XMSS (index persistence before signing),
   ML-DSA / ML-KEM wrappers.
4. `crates/poe-zk` — the binding STARK. Never externally reviewed.
   Known integration gap, stated in its BENCHMARKS.md: the proved
   fold is not yet bound to the node's accumulator hash H.
5. `crates/poe-node` (testnet node) — networking, resume/bundle
   state handling, history serving. The site of every
   implementation bug found so far (below).
6. `crates/poe-identity`, `poe-epoch`, `poe-wallet`, `poe-msg`,
   `poe-store`, `poe-compute`, `poe-v2`, `poe-mobile`, `poe-net`.

## Design questions

**Liveness — mechanism adopted by the owner 2026-11-15,
implemented testnet-profile.** A round whose drawn committee
loses a vote needed for its >2/3 quorum never finalized:
committees are drawn once, votes are one-time, finality is
sequential, and the original design had no re-draw, no timeout,
no skip. Observed live four times on the testnet (rounds 752,
1084, 1231, 1528); recovery was an operator re-anchor. The
adopted cure is the next-committee skip attestation: a vote for
round r+1 may carry a signature witnessing round r empty, and at
>2/3 of r+1's committee, r finalizes as a null round. It was
specified and proved in Lean (`PoE_SkipAttestation.lean`,
against the kernel's Part B finality: the two outcomes coexist
only by naming >1/3 of validators in both supports) before the
Rust landed. Auditors should audit the mechanism as implemented
(README corrections 23–24), including the inert-late-attestation
rule. Formal adoption for mainnet purposes remains the authors'
decision; everything here is testnet profile.

**Still open (authors' decision): the two-caps gap.** The
Step 10 composition proof shows the Tokenomics envelope —
including the first-year grant bound — composes only
conditionally: machine closes hand the oracle cap (400,000,000
on empty price history) where the envelope assumes the module
cap (≤ 100,000). Closing it (hand `min (vcap) (kernelCap)` at
closes, or prove an envelope for oracle-capped histories) is a
design change, not an audit finding against the code as
specified.

## Implementation findings to date (all in the node/finality layer)

Found by the public testnet and its first independent tester
(GitHub issue #1 on this repo), each verified against the code by
the operator, fixed 2026-11-14 with regression tests:

1. **Solo fork (safety).** A bundle-synced node whose catch-up
   dwell expired with no peer material closed the round on its own
   reveals alone — sampling itself as committee and finalizing a
   private fork. Fixed: a round with no peer material is HELD,
   never closed, on both the catch-up and live paths.
2. **Resume wedge (liveness).** A node resuming from its per-round
   state file never cast its vote for its resume round — the
   startup pre-mark covered the first unfinalized round, whose
   vote is only cast in the next round's processing — so the round
   sat one vote short forever when that vote was quorum-critical.
   Fixed: only finalized rounds are pre-marked; every cast vote is
   persisted at cast time so a resume re-casts the same claim.
3. **Stack overflow (robustness).** The GHOSTDAG ordering walk
   recursed over the selected-parent chain; depth grows with
   retained history and killed a Windows node mid-replay (1 MB
   main-thread stack). Fixed: iterative walk, proven
   order-equivalent to the recursion by a property test.
4. **Draw-denominator divergence (safety).** Committee and
   proposer ticket draws divided by the LIVE active-machine count,
   which changes as revocations land — so two nodes holding the
   same blocks could disagree on whether a proposal was
   legitimate and build different DAGs. Invisible at 10 machines
   (the draw always wins); exposed by the 100-machine simnet.
   Fixed: each round's denominator is frozen at its reveal close,
   from its own participant set.
5. **Anchor-round observation (liveness, found at the redeploy).**
   A bundle-synced node sits out its anchor round as an observer.
   After a t0-shifted re-anchor the round was never collected by
   anyone, so every synced node observed an empty round and the
   chain held at the anchor. Fixed: an observed round whose
   dwell expires with no peer material anywhere gets the node's
   own late reveal, plus a settle window before the close.
6. **Serve-window deadlock (liveness, found at the redeploy).**
   History re-serving is push-only and a finstate-resumed node's
   serve window stayed shut, so gossip lost in a mesh-formation
   race was never re-served — owner raced on, loser held forever.
   Fixed: nodes extend their serve window whenever a peer's
   announced position trails their own, and resumed nodes take
   the catch-up dwell on rounds they have not finalized.
7. **Buffered-reveal deadlock (liveness, found at the redeploy).**
   Inbound reveals sit in a buffer until their machine registers;
   the buffer was never flushed inside the network pump every
   wait uses, so two nodes holding a round for each other's
   reveals deadlocked with the material already buffered. Fixed:
   the pump flushes after every poll; held rounds re-publish
   their own reveal with a fresh nonce; the pump re-dials
   configured peers periodically.
8. **Entrypoint checkpoint shadowing (operations, found at the
   redeploy).** The container entrypoint's bundle fetch left a
   stale checkpoint in the data volume; a mid-boot container
   recycle plain-started and synced from the stale (fork)
   checkpoint instead of the fetched anchor. Fixed: the fetched
   bundle is installed as the node's checkpoint too.

9. **DAG memory growth (fixed 2026-11-15).** `poe-dag` kept a
   full ancestor set per block — measured ~4.9 GB steady state
   for the 33k-block epoch-209 state, growing quadratically.
   Fixed with a bounded representation (exact window+frontier
   ancestor oracle, blues/reds as a chosen-link rope, stored
   reds dropped), gated by a differential battery against a
   verbatim copy of the previous implementation and shaped
   replay probes (419 MB peak at 11,991 blocks, testnet width,
   vs the old quadratic curve). See README correction 22.
   Replay *time* keeps the old asymptotics — an auditor should
   treat from-scratch replay pace, not memory, as the remaining
   scaling cost.
10. **Late-attestation false conflicts (fixed 2026-11-15).**
    The first skip-attestation build recorded every attestation
    whenever it was counted, so the conflict query named honest
    machines as double actors (attestations are cast against a
    lagging local record). Fixed: an attestation counted after
    its round finalized is inert — neither tallied nor recorded
    (README correction 24).

An auditor should re-derive each of these from the code and the
issue history rather than trusting this summary, and should look
for the same classes (arrival-order dependence, resume-state
assumptions, unbounded recursion) elsewhere.

## Standing falsifiers

`testnet/BOUNTIES.md` states three public falsifier bounties
(F-Height, F-Clone, F-First-Year) against the live testnet. The
reward amount is the owner's open decision; until it is set,
valid claims earn public acknowledgement and fix credit.

## What is NOT claimed

- No external audit has happened yet.
- The ZK component has no external security review and no
  on-device (phone) benchmarks; VM-CPU timings are in
  `crates/poe-zk/BENCHMARKS.md`.
- V2 (checkpoint bridges etc., `crates/poe-v2`) is gated on V1
  stability in operation and remains closed.
- The testnet root key is public by design (anyone may
  self-attest a testnet identity); it secures nothing of value.
