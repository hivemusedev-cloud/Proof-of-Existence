# Proof of Existence — audit engagement cover

Prepared 2026-11-17 for the owners' sign-off. This is the cover
sheet for engaging the external audit: it states what is being
engaged, on what basis, and what only the owners can fill in.
The technical package it covers is `AUDIT_PACKAGE.md` in this
repository; the public falsifier programme is
`testnet/BOUNTIES.md`.

## What is engaged

An external security audit of the Proof of Existence protocol
implementation — the Rust workspace and its Lean 4 specification
— covering, in the priority order of `AUDIT_PACKAGE.md`:

1. the kernel ledger fold (`poe-kernel`) against the Lean spec;
2. finality and ordering (`poe-finality`, `poe-dag`), including
   the skip-attestation liveness mechanism and the finality
   certificates (light-duty addition #1);
3. the cryptographic layer (`poe-crypto`): the hash H's
   byte-exactness against the Compute Seed, XMSS one-time
   signature discipline, ML-DSA/ML-KEM wrappers;
4. the binding STARK (`poe-zk`) — never externally reviewed; the
   engagement should treat it as a first review, including the
   H-anchored seed and the algebraic fold;
5. the testnet node (`poe-node`): networking, resume/bundle
   state, history serving, the local control surface;
6. the supporting crates (`poe-identity`, `poe-epoch`,
   `poe-wallet`, `poe-msg`, `poe-store` including the Merkle
   companion root, `poe-compute`, `poe-v2`, `poe-mobile`,
   `poe-net`, `poe-vault`).

## The basis the audit starts from (settled 2026-11-17)

The owners settled the open design questions before this
engagement, so the audit reviews a frozen design, not a moving
one:

- **Two-caps: Option A.** Machine closes hand
  `min(vcap, kernelCap)`; the Step 10 composition proof is
  unconditional on that basis (the pre-amendment conditional
  state is preserved in the build record). The tokenomics
  promise and first-year envelope stand exactly as published.
- **Liveness: skip attestation is the mainnet design**, as
  specified and Lean-proved — null rounds, no clocks, no
  re-draw, no threshold decay. It is audited as part of the
  design, like everything else.
- **V2 gate**: closed until the Stage 2 soak criteria are met
  on a real mesh and reported. V2 code is in scope for review;
  its gate is not the audit's to open.
- **Light-duty additions #1 and #2 are built**: finality
  certificates (with their Lean soundness statement) and the
  Merkle companion root. Both are in scope.
- **Standalone (Phase 3)** is prepared, not built; it is not in
  this engagement's scope beyond the vault interface it shares
  with app-mode.

## What the auditor receives

- This repository at the engagement commit (below), including
  the full test suite and the operations log (`testnet/TESTNET.md`).
- `AUDIT_PACKAGE.md` — scope, build/verify instructions, the
  findings history (each fixed finding with its regression
  evidence), and the explicit not-claimed list.
- The Lean specification files and the verification record of
  2026-11-10 (independent re-verification), plus the Step 10
  composition (as amended) and the extension files
  (skip attestation, certificates).
- The design documents (Manual v2.0.0, Tokenomics v1.1.0,
  Compute Seed v0.3.0) — from the owners directly; they are the
  authors' documents and are not in this repository.

## Owner blanks — to be completed before engagement

These are the owners' decisions. Nothing in this package fills
them in, and no figure has been assumed anywhere in the
preparation.

- **Bounty figure** (the standing falsifiers F-Height, F-Clone,
  F-First-Year in `testnet/BOUNTIES.md`, and any audit-period
  bounty): ______________________
- **Audit firm / reviewer**: ______________________
- **Engagement window**: ______________________
- **Engagement commit** (the frozen tree the audit starts
  from): ______________________
- **Disclosure terms** (coordinated-disclosure window, public
  report or private, fix-credit policy): ______________________

## Sign-off

Signed off for engagement, on the basis above:

- Owner 1: ______________________  date: ____________
- Owner 2: ______________________  date: ____________

(A receipt or acknowledgement of this cover by any reviewer is
not an audit result and not an approval of the design; it marks
only that the engagement started from this basis.)
