# What changed in the Rust code — line by line (2026-11-15)

Two features landed: (A) the bounded DAG representation in
`crates/poe-dag`, and (B) skip-attestation liveness in
`crates/poe-finality` + `crates/poe-node`. Everything below is the
actual code, quoted, with what each line does and why.

---

## A. `crates/poe-dag/src/lib.rs` — bounded representation

The old code stored, per block, the FULL set of its ancestors and
full clones of its blue and red lists. At 33k blocks that is
quadratic: ~4.9 GB. The new code stores two small things per block
instead.

### A.1 The GHOSTDAG rope — `GhostCore` (lib.rs ~line 104)

```rust
struct GhostCore {
    chosen: Option<BlockId>,
    mergeset_order: Vec<BlockId>,
    accepted: Vec<BlockId>,
    rejected: Vec<BlockId>,
    blue_score: u64,
}
```

- `chosen` — the block's selected parent (the parent with the
  greatest blue score). One id, not a list.
- `mergeset_order` — the mergeset candidates in consideration
  order. This was already stored per block in the old code.
- `accepted` — only the mergeset candidates THIS block added to
  its inherited blues. Usually a handful.
- `rejected` — only the candidates this block turned red.
- `blue_score` — the block's total blue count, stored as a number
  so it never has to be recomputed by counting a list.

The full blue list of a block is *defined* as
`blues(chosen) ++ [chosen] ++ accepted` — the parent's blues, then
the parent itself, then what this block accepted. So the full list
never needs storing: it is rebuilt by walking `chosen` links.

### A.2 The ancestor oracle — `Anc` (lib.rs ~line 120)

```rust
struct Anc {
    window: Vec<BlockId>,
    frontier: Vec<BlockId>,
}
pub const WINDOW_ROUNDS: u64 = 32;
```

- `window` — the block itself plus every ancestor whose round is
  within 32 rounds of the block's round (`round >= round(block) -
  32`), sorted.
- `frontier` — every deeper ancestor that is a *parent of a window
  block*: the cut set. Every deep ancestor is reachable by
  descending from some frontier member, because to get from the
  block to any deep ancestor you must cross the window's bottom
  edge, and the crossing points are exactly the frontier.

Invariant: any ancestor `a` of the block is in `window`, or in
`frontier`, or is an ancestor of a `frontier` member. That is what
makes the bounded data *exact*, not approximate — for any window
size, even 0.

### A.3 `blues_of` / `reds_of` (lib.rs ~lines 171, 199)

```rust
fn blues_of(&self, id: &BlockId) -> Vec<BlockId> {
    let mut chain: Vec<&GhostCore> = Vec::new();
    let mut cur = *id;
    loop {
        let g = &self.ghost[&cur];
        chain.push(g);
        match g.chosen { Some(c) => cur = c, None => break }
    }
    let mut out: Vec<BlockId> = Vec::new();
    for (i, g) in chain.iter().enumerate().rev() {
        if i + 1 < chain.len() {
            out.push(g.chosen.expect("non-genesis level has a chosen"));
        }
        out.extend(g.accepted.iter().copied());
    }
    out
}
```

- First loop: walk from the block down the `chosen` links to
  genesis, collecting each block's `GhostCore`. This chain IS the
  block's blue ancestry skeleton.
- Second loop: unwind from genesis upward. Each level contributes
  its `chosen` (which is the next block up) followed by the
  candidates that level `accepted`. Concatenated, that is exactly
  the old stored list, byte for byte — the differential battery
  proves it.
- `reds_of` is the mirror: unwind collecting only `rejected`.
- `ghost()` (the public getter) now *builds* a `GhostData` from
  these two walks plus the stored `mergeset_order`/`blue_score`.
  Callers see the same struct as before; only the storage changed.

### A.4 `is_ancestor` (lib.rs ~line 234)

```rust
pub fn is_ancestor(&self, anc: &BlockId, of: &BlockId) -> bool {
    let (Some(ra), Some(ro)) = (self.round_of(anc), self.round_of(of)) else {
        return false;
    };
    if ra > ro { return false; }
    let a = &self.anc[of];
    if ra >= Self::cutoff(ro) {
        return a.window.binary_search(anc).is_ok();
    }
    if a.frontier.binary_search(anc).is_ok() { return true; }
    a.frontier.iter().any(|f| self.is_ancestor(anc, f))
}
```

Line by line:
- Unknown blocks → false. A later round can never be an ancestor
  of an earlier one → false fast.
- If the candidate's round is inside `of`'s window range, the
  answer is a binary search in `window` — the window contains
  *every* ancestor in that round range, so this is exact.
- If it is deeper: it is an ancestor iff it IS a frontier member,
  or it is an ancestor of some frontier member (recursion — the
  frontier member is a real block with its own oracle). Depth of
  recursion is bounded by how many window-widths the chain spans,
  and each level is a small search.

### A.5 `mergeset_of` (lib.rs ~line 283)

```rust
fn mergeset_of(&self, chosen: &BlockId, others: &[BlockId]) -> HashSet<BlockId> {
    let mut out = HashSet::new();
    let mut seen = HashSet::new();
    let mut stack: Vec<BlockId> = others.to_vec();
    while let Some(x) = stack.pop() {
        if !seen.insert(x) { continue; }
        if self.is_ancestor(&x, chosen) { continue; }  // prune
        out.insert(x);
        stack.extend(self.blocks[&x].parents.iter().copied());
    }
    out
}
```

- Depth-first walk from the non-chosen parents. The key line is
  the prune: if `x` is in the chosen parent's past, `x` is not in
  the mergeset AND none of its ancestors are either (transitivity),
  so the whole subtree is skipped. Each mergeset block is visited
  once. The old code computed this from stored full sets; the new
  code asks the oracle instead — same set, proven by the battery.

### A.6 `insert` — building the oracle (lib.rs ~lines 316–355)

```rust
let mut retained: HashSet<BlockId> = HashSet::new();
retained.insert(block.id);
for p in &block.parents {
    let pa = &self.anc[p];
    retained.extend(pa.window.iter().copied());
    retained.extend(pa.frontier.iter().copied());
}
```

- A new block's reachable oracle data is: itself, plus each
  parent's window and frontier. (Any ancestor of the block is an
  ancestor of some parent; each parent's ancestors are covered by
  its window/frontier/descendants-of-frontier, and frontier
  members' own ancestors stay reachable through *their* oracles.)

```rust
let cut = Self::cutoff(block.round);
let mut window: Vec<BlockId> = retained.iter().copied()
    .filter(|x| round_of(x) >= cut).collect();
window.sort(); window.dedup();
```

- Of the retained set, the part at/above this block's cutoff
  becomes its `window` (sorted, for binary search).

```rust
let winset: HashSet<BlockId> = window.iter().copied().collect();
let mut frontier: Vec<BlockId> = Vec::new();
for y in &window {
    let parents: &[BlockId] = if *y == block.id { &block.parents }
                              else { &self.blocks[y].parents };
    for par in parents {
        if !winset.contains(par) { frontier.push(*par); }
    }
}
frontier.sort(); frontier.dedup();
```

- The `frontier` is recomputed from scratch: every parent of a
  window block that is not itself in the window. One subtlety the
  comment in the code flags: the new block is not in `self.blocks`
  yet at this point, so its parents are read from `block` directly
  (an early bug indexed `self.blocks[&block.id]` before insertion).

### A.7 `insert` — the GHOSTDAG decision (lib.rs ~lines 357–405)

- Genesis gets an empty core. Otherwise:
- `chosen` = the parent with the greatest blue score, ties by
  smallest id (unchanged rule).
- `mergeset` from A.5; sorted into consideration order (decreasing
  blue score, ties by id — unchanged).
- `blues` starts as `blues_of(chosen)` + `chosen` (materialized
  once, here, at insert).
- Each candidate: count how many current blues are in its
  anticone — `!is_ancestor(y, cand) && !is_ancestor(cand, y)` —
  using the oracle. If the count is ≤ k, the candidate is accepted
  (pushed to `blues` and `accepted`); else it goes to `rejected`.
- Only `accepted`/`rejected`/`mergeset_order`/`blue_score` are
  stored. The materialized `blues` list is dropped at the end of
  insert — that drop is the entire memory saving.
- `linearize`/`append_order` are unchanged (the iterative walk
  from the residue phase).

### A.8 What proves A is the same DAG

- `crates/poe-dag/tests/old_dag.rs` — the previous implementation,
  verbatim, renamed `OldDag`, kept as a test-only reference.
- `crates/poe-dag/tests/differential.rs` — random DAGs at
  k = 0..3 comparing all-pairs `is_ancestor`, linearization, blue
  scores, ghost blues/reds/mergeset order, selected tip; a 6-wide
  × 300-round mesh (past the 32-round window); a 2,000-block
  chain. 10/10 pass.
- `crates/poe-dag/examples/replay_probe.rs` — shaped replay
  measuring peak RSS: 3,595 blocks, checksum identical old vs new,
  72 MB vs 1,696 MB; 11,991 blocks at width 10: 419 MB (new only —
  the old curve does not run there on this machine).

---

## B. `crates/poe-finality/src/lib.rs` — skip attestation

### B.1 The two primitives (lib.rs ~lines 67–74)

```rust
pub const NULL_BLOCK: BlockId = [0u8; 64];

pub fn skip_message(round: u64) -> H512 {
    h("skip", &[Part::Nat(round)])
}
```

- `NULL_BLOCK` — 64 zero bytes: what a round finalizes *with*
  when it closes empty. It is the Lean extension's "side 0". It is
  never a DAG block; anywhere a finalized id is read as a beacon
  or tip, zero already means "none", so null rounds slot into the
  existing fallbacks.
- `skip_message` — the exact bytes an attestation signs: the
  domain-separated hash `h("skip", round)`. The `"skip"` domain
  tag means an attestation signature can never be replayed as a
  vote signature or moved to another round.

### B.2 The vote gains a field (lib.rs ~line 97)

```rust
pub struct Vote {
    pub machine: u64,
    pub round: u64,
    pub block: BlockId,
    pub sig: XmssSignature,
    pub skip: Option<XmssSignature>,
}
```

- `skip` — a SECOND XMSS one-time signature, over
  `skip_message(vote.round - 1)`. Read it as: "my vote is for
  `block` in round `round`; and I additionally witness that round
  `round - 1` closed empty." The attesting committee is therefore
  round r+1's committee for round r — the next seat, exactly as
  the Lean spec models it.

### B.3 Verification in `vote()` (lib.rs ~lines 476–495)

```rust
if let Some(ssig) = &vote.skip {
    if vote.round == 0 { return Err(FinError::BadSignature); }
    if !xmss::verify(&info.xmss_root, info.xmss_height,
                     &skip_message(vote.round - 1), ssig) {
        return Err(FinError::BadSignature);
    }
    if self.used_leaves...contains(&ssig.leaf) {
        return Err(FinError::LeafReuse);
    }
}
```

- Runs BEFORE the registry claim, next to the main signature
  check. A skip on round 0 is malformed (there is no round −1).
  A bad skip signature or a reused XMSS leaf refuses the WHOLE
  vote — a forged attestation never rides a valid vote.
- After the main leaf is burned, the skip leaf is burned too:
  `used_leaves[machine].insert(ssig.leaf)`. XMSS leaves are
  one-time; the attestation spends one exactly like a vote does.
- Note the Duplicate fast-path above returns before any of this:
  attestations are counted from the canonical (first accepted)
  vote only.

### B.4 Counting, in the Accepted path (lib.rs ~lines 510–540)

```rust
if vote.skip.is_some() && vote.round >= 1 {
    let attested = vote.round - 1;
    if !self.finalized.contains_key(&attested) {
        let set = self.skip_votes.entry(attested).or_default();
        set.insert(machine);
        let scount = set.len() as u64;
        if scount * 3 > 2 * committee_size {
            self.finalized.insert(attested, NULL_BLOCK);
        }
    }
}
```

Line by line:
- Only canonical votes reach here (the registry claim said
  Accepted), so one machine counts once per round no matter how
  many copies of its vote arrive.
- `attested = vote.round - 1` — the round being witnessed.
- `if !self.finalized.contains_key(&attested)` — THE INERT-LATE
  RULE (correction 24): if the attested round already finalized,
  the attestation is inert — not tallied, not recorded. This is
  what keeps the conflict detector honest.
- Otherwise the attestor joins `skip_votes[attested]`
  (`HashMap<u64, HashSet<u64>>`: attested round → attestors).
- The threshold is the protocol's own: `count * 3 > 2 *
  committee_size`, where `committee_size` is the size of THIS
  vote's round committee (the attesting body), its denominator
  already frozen at reveal close by the residue-phase fix.
- Crossing it inserts `finalized[attested] = NULL_BLOCK`. The
  mirror check in the block path (`!finalized.contains_key` before
  inserting a block) makes precedence structural: whichever
  outcome lands first is final; the other can never overwrite it.

### B.5 The queries (lib.rs ~lines 342–375)

```rust
pub fn skip_tally(&self, round: u64) -> (u64, u64)
```
- (attestations recorded for `round`, size of round+1's
  committee). Diagnostics + tests.

```rust
pub fn skip_conflicts(&self) -> Vec<(u64, u64, BlockId)> {
    for (round, attestors) in &self.skip_votes {
        if let Some(winner) = self.finalized.get(round) {
            if *winner != NULL_BLOCK {
                for m in attestors {
                    if self.canonical_vote.get(&(*m, *round)) == Some(winner) {
                        out.push((*m, *round, *winner));
                    }
                }
            }
        }
    }
}
```
- For every round that finalized with a real block, name every
  machine that both attested it empty (live attestation — see
  B.4) and cast the canonical vote for the winning block. These
  are exactly the double actors the Lean theorem
  `skip_and_finality_name_a_third` bounds: if both outcomes ever
  reached quorum on one merged record, this list holds >1/3 of
  the validators.

### B.6 Persistence and wire format

- `FullSnapshot` gains `skip_votes: Vec<(u64, Vec<u64>)>`;
  `snapshot_full` exports the tallies at/above the prune floor,
  `restore_full` rebuilds the map. `prune_before` prunes
  `skip_votes` with the other per-round state.
- `encode_vote` appends a trailing section: byte `1` + the skip
  signature's fields, or byte `0`. `decode_vote` reads it only if
  bytes remain — encodings written before the extension decode
  with `skip: None`. Old peers and old captures stay readable.

### B.7 The battery — `crates/poe-finality/tests/simnet_skip.rs`

- `lost_votes_stall_is_witnessed_and_the_chain_advances` — 10
  machines, all but one of round 5's votes lost: all 16 rounds
  finalize, round 5 is `NULL_BLOCK`, the tally crossed 2/3 of
  round 6's committee, no conflicts.
- `block_finality_takes_precedence_over_attestations` — every
  vote attests indiscriminately: no round finalizes null, and no
  recorded tally crosses (in this harness attestations are
  counted after their rounds finalized → inert).
- `skip_conflicts_name_live_double_actors` — hand-driven
  delivery: one attestation counted while its round is open, from
  a machine that also voted for the block that round later
  finalized with; the detector names exactly it.

---

## C. `crates/poe-node/src/testnet.rs` — the node side

### C.1 Applying a null round (testnet.rs ~line 1120)

```rust
if bid == poe_finality::NULL_BLOCK {
    println!("NULL round={} closed empty by skip attestation", self.next_apply);
    self.next_apply += 1;
    continue;
}
```

- `apply_finalized` walks finalized rounds in sequence. Before
  this change, a null round would have waited forever for a block
  that is not in the DAG. Now: log it, advance `next_apply`, move
  on. No ops are decoded, nothing is applied — a null round has
  no acts, and epoch closes (which count finalized rounds) proceed
  past it.

### C.2 Casting the attestation (testnet.rs ~line 2155)

```rust
let skip = if target_round >= 1
    && !self.fin.finalized.contains_key(&(target_round - 1))
{
    let msg = poe_finality::skip_message(target_round - 1);
    self.keys.xmss.sign_persistent(&self.keys.xmss_path, &msg).ok()
} else {
    None
};
```

- At the vote cast site in `process_round`, after the vote's own
  signature: if the previous round is still unfinalized in this
  node's record, sign `skip_message(target_round - 1)` with
  `sign_persistent` (the XMSS signer that persists the incremented
  leaf index BEFORE signing — a crash can never reuse a leaf).
- Signing failure degrades to `skip: None` via `.ok()` — an
  attestation problem never blocks the vote itself.
- The vote is then built with `skip`, published, fed to
  `self.fin.vote(vote)`, and the finstate is written immediately
  (the residue-phase rule: a cast claim must survive a crash).

### C.3 The resume re-cast site (testnet.rs ~line 1470)

- The same rule at the restart path: when a resumed node re-casts
  its own unfinalized votes (same claim, fresh leaf — a Duplicate
  everywhere, never evidence), each re-cast carries a skip
  attestation under the same condition (attested round still
  unfinalized in the restored record), so a repaired vote can
  still witness.

### C.4 Finstate `POEFIN3` (testnet.rs ~line 517)

```rust
// POEFIN3: adds the skip-attestation tallies (skip_votes).
const FINSTATE_MAGIC: &[u8; 8] = b"POEFIN3\0";
```

- `write_finstate` appends the `skip_votes` section after the
  owed/cast counters; `read_finstate` reads it into the restored
  `FullSnapshot`. The magic bump follows the established pattern:
  a `POEFIN2` file is refused and the node degrades gracefully to
  the epoch-bundle resume instead of bricking.

---

## What did NOT change

Consensus and money rules are untouched: the five acts, the draw
rules (denominators were already frozen in the residue phase),
grant math, epoch closes. The DAG change is storage-only, pinned
by the differential battery. The liveness change adds a message
type and a finalization path for rounds that previously could
not finalize at all; it cannot rewrite a finalized round.
