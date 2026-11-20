# Proof of Existence — external audit package

Prepared 2026-11-14 for an external auditor; refreshed
2026-11-17 (the owners settled the open design questions that
day — two-caps, liveness adoption, the V2 gate rule — and the
light-duty additions #1/#2 were built; the engagement cover is
`AUDIT_ENGAGEMENT.md`). Refreshed again 2026-11-20: first live
epoch closes and certificates on the local mesh (epochs
210–214), the skip attestation live-proved, findings 12–14
added (the mesh re-drive, README correction 35), and the
standalone D4/D5/D7 defects resolved with dispositions. This document is the map: what the code
is, how to build and verify it, what has already been found (by
the operator, by the public testnet, and by an independent
tester), and where the open questions live. Nothing in this
package has been audited externally yet — arranging that audit
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
   revocation, finality. Since 2026-11-17 also the finality
   certificates (`poe-finality::cert`, light-duty addition #1):
   emission at epoch closes and evidence-only verification, with
   the Lean soundness statement in the extension tree
   (`PoE_Certificates.lean`).
3. `crates/poe-crypto` — the hash H (must stay byte-exact against
   the Compute Seed), XMSS (index persistence before signing),
   ML-DSA / ML-KEM wrappers.
4. `crates/poe-zk` — the binding STARK. Never externally reviewed.
   The fold's seed is H-anchored since 2026-11-16 (finding 11);
   the fold itself is still algebraic, not an in-circuit
   Poseidon2 accumulator — the review should judge that choice.
5. `crates/poe-node` (testnet node) — networking, resume/bundle
   state handling, history serving. The site of every
   implementation bug found so far (below). The local control
   surface (no network listener) now also serves the epoch
   certificates and note proofs; its dispatch is part of this
   scope.
6. `crates/poe-identity`, `poe-epoch`, `poe-wallet`, `poe-msg`,
   `poe-store` (since 2026-11-17 including `poe-store::merkle`,
   the Merkle companion root of light-duty addition #2: sorted
   births/deaths/machines sections, inclusion and absence
   proofs), `poe-compute`, `poe-v2`, `poe-mobile`, `poe-net`,
   `poe-vault` (key custody behind the KeyVault interface,
   2026-11-16; backends: the FileVault software stub, the
   Secret Service keyring, Windows DPAPI and macOS Keychain —
   the platform backends added 2026-11-17 are compile-verified
   for their targets and exercised under Wine where possible,
   not yet audited on-device; the libp2p peer key is not yet
   behind the interface — stated in the crate docs).

## Design questions

**Liveness — adopted for mainnet by the owners 2026-11-17,
frozen as the mainnet design.** A round whose drawn committee
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
rule, **as part of the design** — the 2026-11-17 decision froze
it (null rounds, no clocks, no re-draw, no threshold decay);
everything still ships testnet profile until the gates open,
but the design question is closed.

**Two-caps — CLOSED by the owners 2026-11-17 (Option A).** The
Step 10 composition proof had shown the Tokenomics envelope —
including the first-year grant bound — composing only
conditionally: machine closes handed the oracle cap (400,000,000
on empty price history) where the envelope assumes the module
cap (≤ 100,000). The owners' fix: closes hand
`min(vcap, kernelCap)`. In the Lean composition the machine now
hands `min (vcap hist) (kernelCap false L)` (the unsealed
reading, proved the smaller of the two), the envelope is proved
for capped runs via grant monotonicity, and the composition's
envelope and first-year theorems are **unconditional** (the
pre-amendment conditional state is preserved in the build
record; the envelope and every tokenomics number stand exactly
as published). In the Rust, the epoch close's cap was already
the module-side `cap_p` and never an oracle cap; a battery now
pins `cap_p ≤ mod_cap ≤ 100,000` across profiles and economies
(README correction 26). The oracle-cap envelope was not pursued,
per the decision.

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
11. **Unbounded retained history (fixed 2026-11-16).** Even
    with the bounded per-block representation (finding 9), the
    DAG retained every block since genesis, so memory still
    grew with chain length. Fixed: epoch compaction under a
    pruning-point + reference-closure rule with seed-aware
    snapshot/bundle restore (README correction 25), gated by a
    lockstep compaction replay gate on fork-heavy shapes. The
    gate caught two implementation bugs before they shipped
    (a seed-closure scan gap and a window round
    misclassification) — both are documented in correction 25;
    an auditor should re-derive the discharge rules (chosen
    links cut into materialized base colour lists, parent links
    discharged into seed maps) from `Dag::prune` rather than
    trusting this summary. Also closed in the same pass: the
    ZK fold's seed is now anchored to the node's `H`, so a
    binding proof cannot be re-targeted between kernel objects;
    the fold itself remains algebraic pending the external ZK
    review (see "What is NOT claimed").

12. **Skip attestation unreachable through the node wiring
    (liveness, found 2026-11-20).** The mechanism (finding
    context: the adopted liveness cure) was correct in
    poe-finality and in Lean, but the NODE could never deliver
    it: votes lag one round, so skip(r) rides the vote cast in
    process_round(r+2) — whose gate fails on r itself, sets the
    node observing, and observing suppressed the vote. A stalled
    round therefore sat forever while its would-be attesters
    repeatedly observed and cast nothing. The engine-level
    battery could not see this (it constructs votes directly).
    Fixed: the vote step casts despite observing when the
    observation is this round's own gate failure. Live-proved
    the same night (`NULL round=3446` on both live nodes; a
    unanimous 3/3 NULL of the re-anchor round 3440). An auditor
    should treat node-wiring reachability of every engine
    mechanism as in-scope: a proved mechanism the wiring cannot
    invoke is not a liveness property.
13. **Bundles carried post-sync-point finality (safety, found
    2026-11-20).** The bundle snapshot is the base snapshot by
    design (no working state), but its finalized map silently
    included the sync round's own finality whenever the maker's
    epoch close ran a round late — so two bundles for the same
    epoch disagreed about the sync round, and joiners inherited
    (or lacked) a decision they never took part in; in the
    epoch-215 re-anchors this forked finality by bundle choice.
    Fixed: write_bundle truncates finalized to the sync point.
    An auditor should check every snapshot/restore path for the
    same class: state a format claims not to carry, carried
    anyway at a boundary.
14. **Catch-up subset closes (safety, found 2026-11-20;
    mitigations in; the one liveness gap was pinned and
    fixed the same day — README correction 36 — and the
    general question below stays open for the audit).** close_round_reveals
    freezes a round's participant set from whatever has arrived
    locally. In catch-up (all deadlines past) nodes closed on
    subsets: divergent committees for round 3361 that no message
    could heal; an EMPTY close (committee of nobody); and a
    committee-of-one close that NULL-finalized a round on a solo
    attestation while peers finalized its block — the Lean
    quorum-intersection argument assumes a common reveal set,
    and the implementation did not guarantee one in catch-up.
    Mitigations shipped (README correction 35): quiescence
    settle for past-round closes (any material change restarts
    a 6 s window), self-reveal re-derivation for unfinalized
    rounds, the anchor exception keyed on reveals rather than
    blocks, an end-of-round park replacing the catch-up orbit,
    and finding 13's truncation. With them, a three-node
    re-anchor from one identical bundle agreed unanimously on
    every finalized round. The one liveness gap those
    mitigations left — a node's own reveal missing from its
    own close, desynchronizing one committee view by one
    member and leaving a round one vote short (a stall, not
    a fork) — was pinned to the settled-hold's reveal
    re-derive, which abstained while the node was observing,
    and fixed (README correction 36): observing no longer
    suppresses a node's own reveal in the settled-hold. On
    the fixed binary, a re-anchor from the same identical
    bundle closed epochs 215, 216 and 217 on all three nodes
    with identical roots, and the exact round that had
    stalled (3443) finalized as a block on all three. The
    general question — how a catching-up node proves its
    reveal set complete before freezing it — is named here
    for the audit and stays open by the owners' instruction:
    the auditors get the deep question and the fixed
    behaviour. The mitigations are timing-based, and the
    operators do not claim they are a proof.

15. **Cold-resume announcement starvation (liveness, found
    2026-11-20; fixed the same day — README correction 37).**
    A finstate resume starts with an empty announcement
    table: only bundle syncs pre-register the machine set,
    a resume registers only itself, and its one startup
    publication fires before the gossip mesh forms.
    Registrations landed only at round boundaries, so three
    nodes resumed together parked inside the first round's
    hold — which pumps buffers but never landed
    registrations — waiting for peer material that could
    not be submitted for unregistered machines. Any cold
    restart of the whole mesh stranded it the same way, a
    direct threat to the Stage 2 soak's consecutive-days
    criterion on a host with frequent replacements. Fix:
    the waiting loops (catch-up dwell, settled-hold,
    end-of-round park) run an announcement tick on the
    serve tick's cadence — land buffered registrations,
    flush the reveals waiting on them, re-publish the
    node's own announcement with a fresh nonce. Verified
    live: three cold resumes from the epoch-218 state
    closed epochs 219 and 220 unanimously. The pattern is
    the same class as findings 12–14 (resume-state
    assumptions); the operators note it took a real cold
    restart of the full mesh to expose, as with finding 12.

An auditor should re-derive each of these from the code and the
issue history rather than trusting this summary, and should look
for the same classes (arrival-order dependence, resume-state
assumptions, unbounded recursion) elsewhere.

## Built 2026-11-17 (in scope, unaudited like the rest)

- **Finality certificates** (light-duty addition #1, README
  correction 27): `poe-finality::cert` + node emission at epoch
  closes + control-surface serving. The Lean soundness statement
  (`PoE_Certificates.lean`) is at the kernel's Part B
  abstraction, like the skip extension's. Stated boundaries in
  the module docs: no certificate for a null-closed epoch in
  this evidence shape, and the certificate's `revoked` list is
  emitter-asserted (monotone across the chain, cross-checkable
  between sources) — the one field not self-evidencing.
- **Merkle companion root** (light-duty addition #2, README
  correction 28): `poe-store::merkle` — sorted sections,
  inclusion/absence proofs, named in the certificate beside
  `state_root`; the state root's own formula is unchanged.
- **Phase 3 (standalone) image — built 2026-11-18** (after this
  section's original preparation note): Debian bookworm amd64,
  A/B read-only rootfs slots, `poe-node.service` baked, epoch-209
  bundle baked, first-boot identity ceremony (no identity baked).
  The `poe-update` agent implements poe-update-1 (≥2-of-3 ML-DSA
  over the canonical manifest, anti-rollback counter, trial boot,
  health check → bless or rollback+quarantine; battery 11/11) and
  cannot sign; the trust store ships EMPTY and the agent verifiably
  refuses the shipped manifest against it. The D3-fixed image boots
  clean to a login prompt and performs its first-boot ceremony.
  Marked DEV/TESTNET ONLY (vault is a file stub). Defects D4/D5,
  open at the last refresh, were root-caused 2026-11-19/20 to ONE
  mechanism — rootfs directories stamped mode 02770 root:nogroup
  by the build sandbox, so every dedicated-user service failed at
  exec (203/EXEC) while root services worked; the build now
  normalizes modes and asserts none remain (README correction 35).
  systemd-resolved additionally failed on mount namespacing
  against the read-only root and is masked in the image as a
  recorded design disposition (name resolution is not a node
  dependency). D7 (found in the same pass): the baked unit
  plain-started the node, which refuses an empty data dir; a start
  script now syncs from the staged bundle iff no store exists.
  With those fixes the guest node runs end-to-end (identity
  created, bundle synced, control socket answering, HOLDing
  peerless as designed). The final default (non-diagnostic)
  build was made 2026-11-20 and its end-state boot
  verification PASSED (BUILD_REPORT.md final addendum); the
  health check's 600 s deadline is a real-hardware parameter
  and was exceeded under emulation on a contended host — it
  is not inflated to fit the emulator. No owner update-signing key
  exists yet; the 2-of-3 offline ceremony is still the owners'
  to perform.

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
- Finality certificates were emitted live for the first time on
  2026-11-20 (epochs 210–214, local three-node mesh, after the
  correction-35 re-drive fixes; cert files on disk in the node
  dirs). The mesh was then stopped in a consistent state with
  one liveness gap open (finding 14); the V2 soak criteria are
  NOT met — a few live epochs are evidence the machinery runs,
  not the consecutive-live-days soak the gate requires. The
  public Railway node remains on its earlier fork lineage
  pending the owner's bundle-URL flip (rested at the owner's
  instruction), so "live testnet" claims cover the local mesh,
  not the public node.
- The standalone image is built and boots, and with the D4/D5/D7
  fixes its guest node runs end-to-end (see above), but it is
  DEV/TESTNET ONLY: its vault is a file stub, its trust store is
  empty (no owner update-signing key exists yet). The final
  default build + end-state boot verification are done
  (2026-11-20, PASSED; BUILD_REPORT.md final addendum).
