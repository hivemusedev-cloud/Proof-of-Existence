# poe-dag bounded-memory redesign — DESIGN NOTE (proposal, not implemented)

Status: prepared 2026-11-15 for HiveDevs/AdminMuse review. No code changed.
Implementation starts only on approval; the equivalence gate in §5 is part
of the work, not an optional extra.

## 1. Problem

`Dag` retains, for **every** block, two full copies of its past:

- `ancestors: HashMap<BlockId, HashSet<BlockId>>` — the block's entire
  ancestor set (lib.rs:79, built at insert, lib.rs:154–159);
- `GhostData.blues` / `GhostData.reds` — the full blue/red lists of the
  block's past, cloned from the selected parent at every insert
  (lib.rs:192–206).

Both are Θ(|past|) per block, so memory is Θ(N²) in the block count.
Measured on the live testnet node: ~2 GB RSS at the ~20k-block state
(2026-11-14 morning), **~4.94 GB at the 33k-block epoch-209 state** the
same evening. Consequence already in force: the 8 GB host VM runs exactly
one testnet node; node2/node3 are retired until this is fixed. Growth is
structural, so every future epoch makes it worse.

## 2. Exact query surface (verified by grep, 2026-11-15)

Nothing outside `crates/poe-dag` reads `ancestors`, `ghost()`,
`is_ancestor`, `blues`, `reds`, or `mergeset_order`. The external API
actually used (poe-finality, poe-node, tests) is only:

`Dag::new`, `insert`, `get`, `blocks`, `tips`, `selected_tip`,
`blue_score`, `linearize`, `DagError`, `encode_block`/`decode_block`.

Inside `insert`, the stored past is used for exactly three things:

1. **Mergeset**: (⋃ non-chosen parents' ancestor sets) ∖ chosen's set
   (lib.rs:176–184).
2. **Anticone test** per mergeset candidate `cand` against the growing
   blues list: count blues `y` with `y ∉ past(cand)` and
   `cand ∉ past(y)`; blue iff count ≤ k (lib.rs:195–206).
3. Serving the same two operations for future inserts (the child's own
   stored set).

`linearize`/`append_order` use only `ghost.chosen` and
`ghost.mergeset_order` — **not** blues/reds. `reds` are never read
anywhere after being written.

## 3. Structural facts the design relies on

- Ancestors always have strictly smaller rounds (parents are earlier
  tips). So for `round(y) < round(cand)`, `cand ∈ past(y)` is impossible,
  and vice versa — half of every anticone test is decided by round order.
- Ghost data is computed once at insert from already-present parents and
  never changes. The linearization is a pure function of the block set;
  any representation that answers the §2 queries identically produces
  **bit-identical** orders and blue scores. No consensus change.
- The `Dag` is not persisted: nodes rebuild it by replaying blocks from
  the store/bundle at start. (To be re-verified during implementation:
  finstate carries finality state incl. `draw_base`, not ghost data.)
  So the internal representation can change with no wire/store/finstate
  format change and no migration.

## 4. Proposed representation

Per block, retain only O(mesh-width) data:

- `parents`, `chosen`, `blue_score`, `mergeset_order` (as today —
  mergeset size is bounded by tip divergence, not by chain length, in a
  round-structured mesh; the §5 gate measures it on the real bundle).
- **Blues as a persistent rope instead of a cloned Vec**: store per block
  `blues_link = chosen` plus the list of candidates accepted at this
  block (usually empty or tiny). The full blues list of any block is
  recoverable by walking chosen-links. Per insert, materialize the
  chosen parent's blues once (O(blue_score) time, freed after insert) —
  the same order of time today's insert already spends cloning ancestor
  sets, but O(1) retained memory instead of O(past). Optional tip cache:
  keep the materialized blues Vec for current tips only (few, invalidated
  when a tip gains a child).
- **Drop stored `reds`** (write-only today; recomputable if ever needed).
- **Ancestors replaced by an exact bounded oracle**:
  - Per block store `past_window`: ancestors with
    `round > round(b) − W` (W = 64 rounds = 4 epochs; a speed/memory
    constant only), plus `frontier`: the minimal cut set of ancestors at
    or below the window floor (ancestors of b that are parents of blocks
    in b's retained past but lie below the floor themselves).
  - `is_ancestor(a, b)`: if `round(a)` is inside b's window, answer from
    `past_window`; else answer `a ∈ frontier(b)` or
    `∃f ∈ frontier(b): is_ancestor(a, f)` — recursion depth
    ≈ chain_length / W, each level a bounded scan. **Exact for any
    W ≥ 1** — it is reachability decomposed at cut sets; no honesty or
    connectivity assumption, so no consensus-visible approximation.
  - Mergeset (§2.1) becomes a DFS from the non-chosen parents, pruned
    wherever the oracle says `x ∈ past(chosen)`; each mergeset block is
    visited once.
  - Anticone test (§2.2) uses the oracle + the round-order shortcut (§3).

Retained memory per block: O(W × width + |frontier| + |mergeset_order|)
— all independent of chain length → **O(N) total**. Insert time stays
O(past) worst-case (rope walk + oracle), the same order as today's
set-cloning insert; the binding constraint being fixed is memory.

## 5. Equivalence gate (all must pass before the node uses this)

1. **Recorded-bundle replay differential**: replay the epoch-209 anchor
   bundle (`testnet/bundle.bin`, 33k blocks) through the old `Dag`
   (pinned copy) and the new one; assert identical `linearize()` output,
   identical `blue_score` for every block, identical `selected_tip` at
   every epoch boundary.
2. **Differential fuzz**: the existing insertion-order-independence
   battery plus random-DAG trials comparing old vs new on order, blue
   scores, and `is_ancestor` for all pairs on small DAGs.
3. **Memory gate**: replay RSS at the 33k-block state < 500 MB
   (vs 4.94 GB today), measured, not estimated.
4. Full workspace suite green, including `simnet_scale` and the
   small-stack linearization regression test.
5. poe-dag's own unit tests that read `ghost().blues/reds` are updated
   to the rope materializer (test-only helper), or `GhostData` keeps a
   debug materialization — decided in implementation, called out in the
   change notes either way.

## 6. Non-goals and risks

- No change to consensus rules, wire format, store format, or finstate.
- Worst case on adversarial DAG shapes (extreme tip divergence): the
  oracle degenerates toward full walks — insert gets slower, never
  wrong. The bundle gate (5.1) covers the real shape; the fuzz (5.2)
  covers small adversarial shapes.
- `mergeset_order` retention is the one remaining per-block cost that is
  divergence-bounded rather than constant; if the gate shows it large on
  the real bundle, a follow-up can reconstruct it from the rope at
  linearize time instead of storing it.
