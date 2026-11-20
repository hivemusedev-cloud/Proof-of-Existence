# poe-testnet-1 — join the public testnet

**Proof of Existence (PoE)** is a peer-to-peer electronic cash and
communication protocol. This is its first public testnet: a live
network running the Rust implementation in this repository, with the
three falsifier bounties in [BOUNTIES.md](BOUNTIES.md) standing
against it.

Testnet coins are worthless. The chain can be reset by publishing a
new spec; what carries forward is the evidence — every break found
here makes the protocol stronger before any mainnet exists.

## The chain

| | |
|---|---|
| Name | `poe-testnet-1` |
| Genesis hash | `6107532c003ef90c66a1fb1151436803600a7e3600c312b96e6639b4304ab35f9c6776a8dc9994cff8064a5122022a8edc7966956860cfbbd50e4360d4e3de8e` |
| Genesis time (t0) | originally 2026-11-14 00:30:00 Asia/Dhaka (+06) (unix `1794594600`); the operator has since re-anchored the clock at epoch boundaries after liveness stalls (see *Operations log* below) — current t0 unix `1794646677`, under which round 3360 (the epoch-209 boundary) began 2026-11-14 17:45:57 +06. The genesis hash does not depend on t0 and is unchanged. |
| Profile | reference (pot ÷300, window 522, usage floor 1000), V1 fair launch |
| Rounds | 3 seconds each, 16 per epoch (an epoch ≈ 48 seconds) |
| Ordering | BlockDAG + GHOSTDAG (k = 3), ticket lottery (~16 expected proposers/round) |
| Finality | ticket-sampled committee, XMSS one-time votes, > 2/3 = final |
| Ticket chains | 20,001 links — one machine identity serves ≈ 20,000 rounds (≈ 16 hours); then register a fresh identity (below) |
| Spec | [`crates/poe-node/testnet-1.spec`](../crates/poe-node/testnet-1.spec) — frozen; the node refuses to start if its build's spec does not hash to the genesis above |

## Run a node

You need a Rust toolchain (1.9x) and this repository.

```bash
git clone https://github.com/hivemusedev-cloud/Proof-of-Existence
cd Proof-of-Existence
cargo build --release -p poe-node
```

**If the chain has not started yet** (before t0), a fresh node joins
from genesis:

```bash
./target/release/poe-node testnet \
  --dir ~/poe-testnet-node \
  --listen /ip4/0.0.0.0/tcp/41001 \
  --peer /ip4/104.29.200.165/tcp/41001/p2p/12D3KooWLrxxWtsDSX4d3xVswbPVSLmS1PxNpDiFBgwtCx62gVGQ
```

**If the chain is already running**, sync from a bundle published by
any running node (the bootstrap nodes serve theirs, see below), then
start with it:

```bash
curl -O http://104.29.200.165:4180/bundle.bin
./target/release/poe-node testnet \
  --dir ~/poe-testnet-node \
  --listen /ip4/0.0.0.0/tcp/41001 \
  --peer /ip4/104.29.200.165/tcp/41001/p2p/12D3KooWLrxxWtsDSX4d3xVswbPVSLmS1PxNpDiFBgwtCx62gVGQ \
  --sync-from ./bundle.bin
```

The node creates its identity on first start (an ML-DSA device key, a
ticket chain, an XMSS vote key) under `--dir`, self-attests under the
testnet root, announces its machine, and joins the round loop. One
honest warning: deriving the XMSS vote key takes a few minutes of
CPU on every start (the tree is re-derived from its seed, not
stored), so the output below appears only after that pause. Watch
for:

```
CHAIN poe-testnet-1 genesis=…
MACHINE <your machine id>
LISTEN /ip4/…/tcp/…/p2p/<peer id>
CLOSE epoch=0 claimants=… grant_each=… minted_total=… credited=… root=…
```

The `CLOSE` lines are the chain's heartbeat: every honest node prints
the same `grant_each`, `minted_total`, and `root` for the same epoch.
If yours ever differ, you have found something — see BOUNTIES.md.

Your machine earns its first grant at the first close after its join
lands in a finalized block, and vests 1/50 per epoch in which your
node casts every vote it owes (stay online and unrevoked).

## Bootstrap nodes

The first nodes, run by the launch operator on a best-effort basis —
any node can serve as a peer; these are conveniences, not authorities:

- `/ip4/104.29.200.165/tcp/41001/p2p/12D3KooWLrxxWtsDSX4d3xVswbPVSLmS1PxNpDiFBgwtCx62gVGQ` (machine 1123122162023658167)
- `/ip4/104.29.200.165/tcp/41002/p2p/12D3KooWEjHriRjvC6R6pp5JaWWCtFMVV5S3EhXxU8pJUNF87u7g` (machine 11887545442228343284)
- `/ip4/104.29.200.165/tcp/41003/p2p/12D3KooWKZZ92UqEHSv6tJShiJThSQs7reBHgUbWMoD6WRUghaKf` (machine 13754866497659891996 — a rotated identity: the original third bootstrap's keys were lost during operations on 2026-11-14; the fresh identity joined the running chain in epoch 76, see the operations log)
- `/dns4/tokaido.proxy.rlwy.net/tcp/56783/p2p/12D3KooWAqhtJPPgr3W5ryARp6CtYxLdTuEoQvsz2W79H8jGDVpC` (machine 17293328633672825831 — **the public bootstrap**, hosted on Railway since 2026-11-14 08:28 +06; this one *is* reachable from the public internet via Railway's TCP proxy. It synced from the epoch-113 bundle published in this repository at `testnet/bundle.bin`; see `RAILWAY.md` for the deployment. Its own join lands once the network reaches live rounds — see the operations log.)

**Reachability, stated plainly:** the operator's VM sits behind NAT
with no inbound port mapping. External TCP checks (check-host.net,
five locations, 2026-11-13) to the addresses above **time out** — as
of launch these nodes are *not* reachable from the public internet,
and neither is the bundle URL below. They are listed because they
are the chain's seed record (and become usable the moment the
operator's network path changes). Practical ways in today:

- Run a node on any host with a public inbound port (a cheap VPS
  works) and share its `--listen` address as a peer for others —
  the network is whoever is running it.
- Or run it on Railway, whose TCP proxy needs no public host of
  your own: full walkthrough in [RAILWAY.md](RAILWAY.md).
- On a LAN, nodes find each other automatically via mDNS: start
  with no `--peer` at all.
- Two NATed nodes cannot dial each other directly yet (no relay or
  hole-punching in this build) — one reachable node is enough to
  bridge a group.

Sync bundles: the operator serves the current epoch bundle at
`http://104.29.200.165:4180/bundle.bin` (refreshed at every close;
same reachability caveat). Independently of that server, **every**
running node writes the identical bundle to `bundle.bin` in its own
data directory at every epoch close — any operator can hand you a
copy, and `--sync-from` verifies it against the chain spec before
trusting it.

## The testnet root — read this

Joining requires an attestation from the chain's attestation root.
On this testnet **the root's secret key is public** — it is printed at
[`testnet/TESTNET_ROOT_SK.txt`](TESTNET_ROOT_SK.txt) and embedded in
the node for self-attestation — so anyone can mint an identity and
join. That is deliberate: this network tests the one law (claims,
evidence, finality, the money envelope), not identity scarcity.

On mainnet, roots belong to hardware manufacturers, are never
published, and admission is quota-bound per root. Nothing about the
testnet root's publicity carries over; a "break" that merely uses the
public root to create many identities breaks nothing (see the
F-Clone scope note).

## Identity rotation

A ticket chain serves ≈ 20,000 rounds (≈ 16 hours of wall time).
When your node's reveals run out it stops proposing and voting.
Rotate by starting once with a fresh `--dir` (a new identity), or
delete `ticket.seed`, `xmss.key`, and `device.key` from the old
directory to re-identify in place. Your old machine simply goes
quiet; nothing is owed or lost — the testnet keeps no value.

## Known limits of this launch

- Nodes keep no long-term peer exchange yet: if all your `--peer`
  contacts vanish, restart with a live one. mDNS finds nodes on a LAN
  automatically.
- State sync starts from a bundle (an epoch-boundary snapshot served
  as a file); from there the joiner catches up in-protocol — peers
  re-serve the current epoch's blocks, ticket reveals and votes over
  gossip for a while after a new machine registers. A full
  history-sync protocol for arbitrary depths is not built.
- Restarting a node resumes it from the full finality state it
  persists after every round (`finstate.bin` in its data directory):
  stop and relaunch with the same `--dir` and arguments. It rebuilds
  from its exact pre-stop position, re-casts its own votes for
  rounds that never finalized (as *duplicates* at peers, never as
  second claims), and continues in sequence. Without a finstate it
  falls back to the epoch bundle in its directory.
- The launch operator's bootstrap nodes run on one VM behind NAT
  (no inbound reachability from the public internet — see Bootstrap
  nodes); if it is down, anyone can re-bootstrap a peering point
  from this spec — the chain is its nodes, not its first operator.
- A node holds roughly 2 GB of memory while running; the operator's
  8 GB VM sustains three nodes. Size your host accordingly.

## Operations log — 2026-11-14 (read this before trusting liveness)

The current chain is the third genesis of 2026-11-13/14 (t0 00:30
+06). It closed epochs 0–66 identically on three nodes, survived a
single-node restart mid-epoch with state intact, and then taught
its operators the launch's main lesson, stated plainly:

**A round whose committee loses a vote can strand the chain.** A
committee is drawn once, when its round's reveals close, and votes
are one-time claims — there is no re-draw and no second vote. If a
drawn voter crashes, falls an epoch behind, or votes for a
different block because the leading block reached it late, that
round can sit one vote short of finality *forever*, and every later
round waits behind it (finality is sequential). This happened at
rounds 752, 1084 and 1231 — each time after exactly the churn a
public testnet exists to invite (a hub node OOM-killed at ~2 GB per
node on a small VM, restarts, a late joiner in a diverged view).

The operator's recovery each time was a **re-anchor**: every node
re-syncs from the last epoch bundle (the chain's own checkpoint —
ledger state at the last close, which is final and was never in
dispute), the clock's t0 is shifted so the next round starts at a
fresh wall time, and the chain resumes. No finalized state was ever
lost or rewritten; the stranded rounds' unfinalized tail is
discarded. Re-anchors so far: rounds 752, 1072, 1216, 1232, 1456
and 1520 (the last is the current t0 above). The bootstrap nodes
run under systemd supervision (`Restart=always`, starts staggered
because XMSS key derivation is minutes of CPU); supervision keeps
the processes alive, but a restart into a stranded round still
needs the re-anchor above — it is a procedure, not yet a mechanism.

Two honest consequences:

- **Liveness under churn is this testnet's open problem**, and it is
  a *design* question, not an implementation bug: the audited model
  assumes lockstep rounds (its simnet, with Byzantine voters
  withholding, finalizes because committees there are larger and
  delivery is uniform). Whether the protocol gains a liveness
  mechanism (committee re-draw, vote timeouts, larger committees)
  is a decision for the protocol's authors — it will not be patched
  in silently here. Demonstrating a *new* stall shape is a valid
  bounty finding; re-demonstrating this one is documented already.
- A late joiner's join landing is proven: at epoch 76 a fresh
  identity (the rotated third bootstrap) synced from the epoch-75
  bundle, proposed its join, and the close printed **claimants=1,
  grant_each=99999** with the identical state root
  `d68cda776b23a5c9` on independent nodes. Earlier join attempts
  exposed a real bug — a join proposed in a block that never
  finalized was never retried — fixed and documented in the
  repository README (live-network correction 11).

Ghost identities: every wiped-and-recreated node directory leaves
its previous machine registered on the ledger forever (joins are
once-ever and there is no deregistration). Ghosts never reveal, so
they are never drawn into committees; they only dilute the draw
denominator. The ledger currently carries a handful from launch
operations.

### Operations log — 2026-11-14, morning: Railway bootstrap, and the resume wedge

- **A public bootstrap exists.** A fourth node (machine
  17293328633672825831) was deployed to Railway from this repository
  (see `RAILWAY.md`) and started 2026-11-14 08:28 +06, synced from
  the epoch-113 bundle now published at `testnet/bundle.bin` in this
  repo. It is reachable at the `/dns4/tokaido.proxy.rlwy.net/...`
  address in the bootstrap list above. The three NAT'd bootstraps
  peer with it outbound, so the mesh has a public front door for the
  first time.
- **The operator VM was replaced several times** during the morning
  (roughly 04:58, 05:09, 07:20, 09:05 +06), each time wiping the
  systemd units (they live outside the workspace) and killing the
  nodes; node processes are also periodically SIGKILLed by the
  platform and relaunched by systemd. Chain data lives in the
  workspace and survived every replacement; finalised state was
  never lost.
- **New finding — the finstate resume path wedges (implementation
  bug, reproduced 4×).** A node that resumes from its saved
  `finstate.bin` never advances past its resume round: observed at
  rounds 1837 (two nodes), 1853, 1872 and 1874. A node that starts
  fresh from an epoch bundle advances through the same rounds every
  time. Controlled A/B: one node's fresh instance was advancing at
  round 1874; its supervised successor resumed from the finstate the
  fresh instance wrote and froze at 1874. The earlier stalls at
  rounds 752–1528 were attributed to lost committee votes; at least
  the 1837 stall is now shown to be this resume wedge instead — a
  fresh replay of that round finalises from the same served history.
  The wedge cost the network its epochs 114–116 for several hours:
  two finstate-resumed nodes sat at 1837 while a bundle-fresh node
  closed epoch 114 alone (root `0587521404eaae91`).
- **Convergence after the fix:** all three operator nodes were
  restarted fresh from bundles. Independent fresh replays agree
  exactly: epoch 114 root `0587521404eaae91`, epoch 115 root
  `528733ebf31aa1dd`, epoch 116 root `eac66732ae18a099` on all three
  nodes. There is no fork; the credited=2 epoch-114 close seen in a
  pre-rollback filesystem state was superseded by the canonical
  credited=1 replay.
- **Operator mitigation (no protocol change):** the local launcher
  now always starts each node fresh from its own latest bundle
  (rewritten at every epoch close it performs), discarding only the
  unfinalised tail — the re-anchor mechanic, automated per node.
  Under it, all three nodes advance together again and survive the
  platform's kill cycle. The Railway entrypoint shares the latent
  issue: a Railway restart that resumes from its volume would wedge
  the same way; it has not restarted since its bundle start.
  A code-level fix for the resume path is owed and is a decision for
  the protocol's authors, like the liveness mechanism above.
- The network is replaying a backlog (epoch ~118 against a wall
  clock of ~269 at the time of writing) accumulated over the
  morning's outages. The Railway node's join, and any new joiner's,
  lands when the mesh reaches live rounds; an operator re-anchor
  remains the shortcut, at the usual cost of the unfinalised tail.

## Operations log — 2026-11-14 (afternoon): issue #1 retest, and the fix batch

- **Issue #1 retest (independent tester, Windows node).** With the
  fresh epoch-179 bundle the node solo-forked again — epoch 180
  `claimants=1, root=38d3b738…` against canonical `7078c959…`
  (claimants=0); the divergence is exactly his join, the bundle is
  byte-identical to the published one (1,822,628 bytes, sha256
  cc1284f7…), and his minted total is canonical + his 99,999 grant.
  Expected: the dwell fix was owed, not yet shipped. **New finding
  2:** the node then died — `thread 'main' has overflowed its
  stack` — after epoch 181; a Linux run from the same bundle
  survived epochs 180–185. Verified mechanism: the GHOSTDAG
  ordering walk (`Dag::append_order`) recursed over the
  selected-parent chain with no depth bound; depth grows with
  retained history, and the Windows main-thread stack (1 MB) is
  8× smaller than Linux's (8 MB). Linux surviving that window is
  not immunity.
- **The fix batch (all implementation layer; kernel/money rules
  untouched; README corrections 13–17).** (1) A round with no peer
  material is HELD, never closed — the catch-up dwell's
  fall-through is removed and the live close is gated the same
  way. (2) The resume wedge, diagnosed to the line: the startup
  `voted` pre-mark covered every round ≤ next_apply including the
  first UNFINALIZED round, whose vote is cast only in the next
  round's processing — so every finstate resume abstained on
  exactly the round that needed its vote. (This corrects the
  framing above: the wedge was an implementation bug, not a
  design question.) Only finalized rounds are pre-marked now;
  every cast vote is persisted at cast time; the finstate format
  is versioned (POEFIN2) and an unreadable finstate degrades to
  the epoch bundle. (3) `append_order` rewritten iteratively,
  order-equivalence to the recursion proven by property test.
  (4) Replay pace: history serve slices raised 16 → 64 rounds —
  at 16, a deep joiner's slice-bound pace (~5 rounds/min) was
  below the 20 rounds/min wall clock and its backlog grew.
  (5) A sixth finding, from the new 100-machine simnet: committee
  and proposer draws divided by the LIVE active-machine count,
  which moves as revocations land — two nodes holding the same
  blocks could build different DAGs. Each round's denominator is
  now frozen at its reveal close from its own participant set
  (carried in the finstate as `draw_base`). The scale simnet
  (100 machines, 30% Byzantine, 48 rounds, two insertion orders)
  passes with the fix and diverged without it; the 10-machine
  finish-line battery is unaffected (target ≥ active there).
- The launcher mitigation above (always bundle-start) is retired
  with this deployment: plain starts resume from finstate again,
  which is the path the kill/resume drill now exercises.

## Operations log — 2026-11-14 (evening): redeploy and re-anchor

- **Re-anchor (eighth).** The fix-batch binary (README corrections
  13–19) was deployed from the epoch-209 bundle (sync round 3360,
  sha256 c4e9b50f…), with t0 shifted to 1794646677 so round 3360
  reopened at 17:45:57 +06. The bundle is published as
  `testnet/bundle.bin` and, for the Railway node's re-sync, as
  `testnet/bundle-anchor-2026-11-14.bin`.
- **Two further findings fell out of the redeploy itself** (README
  corrections 18–19; audit package findings 5–6): every synced
  node observed the anchor round, which nobody had ever collected
  — the chain held at the anchor until observed rounds learned to
  contribute a late reveal; and a finstate-resumed node's serve
  window stayed shut, so gossip lost in a mesh-formation race was
  never re-served (owner races, loser holds) — serve windows now
  extend toward any peer whose announced position trails, and
  resumed nodes dwell on unfinalized past rounds like synced ones.
- The local launcher no longer wipes on start: plain starts resume
  from finstate (bundle as fallback), which is what the
  kill/resume drill exercises from here on.
- **Railway landed on the fork lineage, not the anchor** (same
  evening): its volume checkpoint was a bundle from the fork the
  first tester marched with it earlier in the day (epoch 162,
  minted 300000000499998 — the canonical 399999 plus that fork's
  99,999 grant). The entrypoint fetched the epoch-209 anchor and
  wiped the store, but a mid-boot container recycle plain-started
  and the binary's fallback synced from the stale checkpoint
  (README correction 21). The entrypoint now installs the fetched
  bundle as the node's own checkpoint; POE_BUNDLE_URL was pointed
  back at `testnet/bundle.bin` (the same anchor bytes) to trigger
  a clean re-sync. The fork lineage is abandoned: sequential
  finality means its nodes can never rejoin this chain; their
  data dirs stay as evidence.
- **DAG memory ceiling measured:** a node holding the epoch-209
  state sits at ~4.9 GB RSS (poe-dag keeps a full ancestor set
  per block; growth is quadratic in chain length). The operator
  VM therefore runs ONE local node now (node1; node2/3 stopped) —
  the three-node local mesh is retired until the ancestor
  representation is bounded. See the README's open finding.

## Operations log — 2026-11-15: liveness mechanism and bounded DAG land

- **Skip attestation implemented** (owner-adopted design,
  README corrections 23–24): a vote for round r+1 may carry an
  XMSS signature over `skip_message(r)`; at >2/3 of r+1's
  committee the stalled round finalizes as a null round
  (`NULL_BLOCK`). Block finality is never overridden; late
  attestations are inert. Specified and proved in the Lean
  extension first (`PoE_SkipAttestation.lean`). Finstate format
  is now `POEFIN3`; nodes resuming from `POEFIN2` files degrade
  to the bundle resume as designed. Battery: `simnet_skip` 3/3
  (stall witnessed and closed null; precedence; the conflict
  detector names exactly a live double actor).
- **Bounded DAG representation implemented** (README correction
  22): the ancestor representation behind the 2026-11-14 memory
  ceiling is replaced — exact window+frontier oracle, blues/reds
  as a rope, stored reds dropped. Differential battery against
  the previous implementation passes; shaped replay peaks at
  419 MB for 11,991 blocks at testnet width (old curve:
  quadratic, 1,696 MB already at 3,595 blocks). node1's steady
  RSS on the new binary is to be measured live; the one-node-per
  host limit is expected to lift but is not claimed until
  observed.
- **node1 restarted on the new binary (2026-11-15 ~12:40 +06),
  observed:** its `POEFIN2` finstate was refused by the new
  `POEFIN3` binary and it fell back to the epoch bundle, exactly
  as designed — `START synced from bundle at epoch 209 (round
  3360); ledger epoch 210 minted 300000000399999`. That first
  start took the bundle resume's wall-clock frontier posture
  (observing, closing nothing alone). The node persisted a
  `POEFIN3` finstate, and from the next restart it is a full
  finstate resume: sequentially processing from round 3361 and
  HOLDing it in the catch-up dwell — `HOLD round 3361: no peer
  material` — the same posture as before the redeploy, waiting
  for a canonical peer. **Steady RSS ~72–74 MB at the epoch-209
  state, against ~4.9 GB on the old binary** — the bounded DAG
  representation verified live at the very state that set the
  ceiling. The canonical head remains the epoch-209 anchor
  until a peer network exists again (Railway is on the fork
  lineage — see the flip note below; nodes 2/3 are stopped).
- **Epoch compaction is NOT in this build**: specified, with an
  exactness analysis showing the naive form can diverge on
  long-lived forks; the safe form is a separate gated step.
- **Railway is still on the fork lineage** (see the 2026-11-14
  evening entry): the POE_BUNDLE_URL flip back to
  `testnet/bundle.bin` remains outstanding at the time of
  writing.

## Operations log — 2026-11-16: epoch compaction lands (residue stage)

- **Epoch compaction implemented** (README correction 25): at
  each epoch close the node prunes the finalized history below
  the closed epoch's first round, anchored at that round's
  finalized block. `Dag::prune` enforces the three conditions
  from the 2026-11-15 exactness analysis — pruning point
  (anchor an ancestor of every tip; prune refuses outright
  while an unmerged fork tip does not descend from it),
  reference closure with discharge (mergeset/colour references
  protect; chosen links are cut into materialized base colour
  lists; parent links are discharged into seed maps), and
  seed-aware restore (snapshots carry the full retained state:
  bundle format `POEBNDL2`, v1 still readable; finstate
  `POEFIN4`). Gate: `crates/poe-dag/tests/compaction.rs` —
  fork-heavy mesh in lockstep, compacting vs never, every
  observable identical; the gate caught two real bugs on the
  way in (seed-closure scan gap; window round
  misclassification), both fixed. A poe-finality test pins
  that the legacy blocks-only restore loses a pruned anchor's
  whole descendant cone on the same snapshot the state restore
  keeps exactly.
- **poe-zk H-binding landed** in the same pass: the fold seed
  is derived from the node's `H` over the binding kind and the
  kernel object's bytes (`anchored_seed`), and
  `verify_anchored` recomputes it — a proof can no longer be
  re-targeted between objects. The fold stays algebraic; an
  in-circuit Poseidon2 accumulator remains deliberately
  unbuilt ahead of the external ZK review.
- **Full workspace suite: 86/86** (79 workspace + poe-finality
  7: simnet 2, simnet_skip 3, snapshot_prune 1, simnet_scale 1
  in release). Logs:
  `~/workspace/poe-build-2026-11-11/test-logs-2026-11-16/`.
- **node1 redeployed on the compaction binary (2026-11-16
  ~10:49 +06), observed:** the unit files had been wiped by a
  VM replacement again — reinstalled, node2/node3 stopped and
  disabled as before, the 6500M memory drop-in re-added. First
  start: the `POEFIN3` finstate was refused by the `POEFIN4`
  reader and the node fell back to the epoch bundle, exactly
  as designed — `START synced from bundle at epoch 209 (round
  3360); ledger epoch 210 minted 300000000399999` — and
  persisted a `POEFIN4` finstate. Second start: full finstate
  resume, HOLDing round 3361 in the catch-up dwell, **RSS
  ~55 MB** at the epoch-209 state. No `PRUNE` line is expected
  live yet: pruning runs at epoch closes, and no epoch can
  close until a canonical peer network exists again — the
  compaction path is verified by the replay gate and the
  restore tests, not yet by a live close.
- **Railway is still on the fork lineage**: the POE_BUNDLE_URL
  flip remains outstanding (dashboard access); this push
  auto-redeploys Railway onto the compaction binary, but its
  volume state is unchanged by that.

## Operations log — 2026-11-16 (later): key-vault interface lands (Phase 0 item 2)

The node's protocol keys moved behind the KeyVault interface
(`crates/poe-vault`, PoE OS flag 1): the trait covers the
device ML-DSA key, the stateful XMSS vote key (the vault
persists a leaf before releasing its signature) and the
ticket chain; the node now loads and signs exclusively
through it, on the FileVault backend — the software stub,
which keeps the exact historical key files and reports
itself not mainnet-eligible. Stated scope: the libp2p peer
transport key is not behind the interface yet (see the
crate docs). Full suite 91/91 (84 workspace + 7
poe-finality; logs
~/workspace/poe-build-2026-11-11/test-logs-2026-11-16/*-vault.log).

node1 was redeployed on the vault binary the same day
(systemd units had been wiped by another VM replacement;
reinstalled, node2/node3 left retired, 6500M drop-in
re-added). Observed on boot: `KEYS backend=file (software
stub) mainnet_eligible=false`; machine unchanged
(1123122162023658167 — the vault reads the same device.key);
full POEFIN4 resume; HOLDing round 3361; RSS ~55 MB.
Railway remains on its fork lineage pending the bundle
variable flip; canonical head is still the epoch-209
anchor.

## Operations log — 2026-11-16 (later still): local control surface lands (Phase 0 item 3)

The node gained its local control surface
(`crates/poe-node/src/control.rs` + the `poe-node ctl`
client): a Unix socket at `<dir>/control.sock`, mode 0600,
JSON-lines, no network listener. Live over it: node status;
the wallet (live notes from the ledger, Existence Container
import/list, offline shows); a transfer queue that
pre-validates with `Ledger::accepts` and drains into the
proposer's op list with re-validation; and poe-v2's genesis
curve in-process for state and quotes — execution
(swap/bridge) refuses with a `gated` error naming the
pending Stage 4 AskAdmin q-b50bcedac227dd454d70955bcd5acdfc.
Full suite 94/94 (87 workspace + 7 poe-finality; logs
~/workspace/poe-build-2026-11-11/test-logs-2026-11-16/*-control.log).

node1 redeployed on the control-surface binary the same
day. Observed: boot log `CONTROL listening on
.../node1/control.sock (local only)`; socket mode 0600;
machine unchanged; POEFIN4 resume, HOLDing round 3361;
RSS ~55 MB. Smoke over the socket, verbatim results:
`status` → joined, epoch 210, head round 3360, minted
300000000399999, v2_gate closed. `wallet.notes` → one live
note, value 100000 (the current window's grant).
`v2.state` → spot 10000000 (P0), pool 3e21 x 3e14.
`v2.quote` buy 1e18 → out 99966677774. `v2.swap` → the
gated refusal. No epoch can close until a canonical peer
network exists, so the transfer queue's live drain is
verified by unit test, not yet by a live proposal.

## Operations log — 2026-11-16 (Phase 1): OS-keyring vault backend + app packaging

Phase 1 (desktop app-mode) opened with its shell-independent
work; the shell itself awaits the owners' technology decision
(Stage 4 AskAdmin item 4a). poe-vault gains a second backend:
the OS keyring (freedesktop Secret Service), selected with
POE_VAULT=keyring. poe-crypto's XMSS key gained the state-bytes
seam (state_bytes / from_state_bytes / sign_persistent_with)
the backend signs through — persist-before-release now runs
through the keyring store. Two findings from the work, both
recorded in the code: (1) the keyring's blocking D-Bus
transport panics inside the node's tokio runtime ("Cannot
start a runtime from within a runtime"), so the node uses
ThreadedKeyringVault — custody on a dedicated thread, trait
calls as channel round-trips — and the vault battery carries
a regression test that drives it from inside a runtime;
(2) no commodity OS store signs ML-DSA/XMSS internally, so
the keyring backend is encrypted-at-rest custody, honestly
not mainnet-eligible, like the stub. App packaging:
APP_PACKAGING.md + `poe-node paths` / `poe-node service-unit`
(per-OS data dirs, control-endpoint names, lifecycle
contract). Full suite 98/98 (91 workspace + 7 poe-finality;
logs test-logs-2026-11-16/*-phase1.log).

Verified live, on a scratch node (removed afterwards): a
fresh node with POE_VAULT=keyring created its identity in a
real GNOME Keyring (home-installed on this VM, which ships
without one), synced from the epoch-209 bundle, ran rounds,
and exited cleanly; a second start resumed from its POEFIN4
finstate with the same machine id and answered `ctl status`
with keys_backend "OS keyring (Secret Service)". node1
redeployed on the same binary, file backend as before:
machine unchanged, POEFIN4 resume, HOLDing round 3361.
Railway remains on its fork lineage pending the bundle-URL
flip (owner's dashboard action, unchanged).

## Operations log — 2026-11-17: Phase 1 completed, Phase 2 started

Phase 1 completion (owner's instruction, 2026-11-17): the
Windows named-pipe control server and the `poe-node ctl` pipe
client landed (same JSON-lines protocol as the Unix socket);
poe-vault gained the two remaining platform backends —
`DpapiVault` (Windows DPAPI-protected files under the data
directory's `dpapi/` folder) and `KeychainVault` (macOS
Keychain generic-password items) — behind the same KeyVault
trait, neither mainnet-eligible, like the others. poe-node
cross-builds for x86_64-pc-windows-gnu (whole tree incl.
libp2p) and poe-vault type-checks for aarch64-apple-darwin.
Full Unix suite re-run green: 98/98. The Electron shell's
control client now speaks the pipe on Windows, and a Windows
portable package was built via electron-builder
(`app/build-win.json`); the NSIS installer needs a 32-bit
Wine on this build host (install in progress at the time of
writing). The owner's on-device verification steps are in
`app/WINDOWS_WALKTHROUGH.md`.

Windows binary exercised under Wine on this host (an
emulation layer — the owner's real Windows run is the
deciding check): `poe-node.exe paths` prints the Windows
data directory and the pipe name; a scratch node with
POE_VAULT=dpapi created its identity entirely in
DPAPI-protected files (device.key, ticket.seed, xmss.key —
Wine crypt32 blobs), logged `KEYS backend=Windows DPAPI
mainnet_eligible=false`, synced from the epoch-209 bundle
(epoch 210, minted 300000000399999), listened on
\\.\pipe\poe-node-scratch-wine, applied round 3361 and
exited cleanly. The first attempt at this run was cut by a
runtime restart during XMSS generation; the completed run
reloaded the two protected files the interrupted run had
written, which is also the unprotect-path evidence.

Phase 2 started the same day (owner's instruction): the
Android identity app was built and packaged as a signed
debug APK on this host (manual kotlinc/d8/aapt2 pipeline —
the sandbox's network policy blocks Gradle's loopback; the
Gradle project is in the tree), and the iOS app sources +
Swift bindings were written for assembly on the owner's
Mac. See `mobile/README.md`. Neither app has run on a
device yet.

node1 was found down after a VM replacement wiped its
systemd unit (the standing pattern) and was restored the
standard way (units reinstalled, node2/node3 left retired,
6.5 GB drop-in re-added); it resumed from its POEFIN4
finstate toward HOLDing round 3361 on the epoch-209 anchor,
as before. Railway remains on its fork lineage pending the
bundle-URL flip (owner's dashboard action, unchanged).

## Operations log — 2026-11-17 (later): owner decisions executed — two-caps closed, certificates + Merkle root built, Phase 3 prepared, audit pack refreshed

The owners settled the five open design questions directly
(2026-11-17): two-caps Option A; skip attestation adopted for
mainnet and frozen; the V2 gate stays closed until the Stage 2
soak criteria are met on a real mesh and reported (the control
surface's gated refusal now states this rule); the standalone
image is Debian-derived with owner-held offline 2-of-3
update-signing keys; the light-duty note approved as scoped,
authorizing the certificate and Merkle-path builds. AdminMuse
was notified facts-only via AskAdmin
(q-34e5b681d37c4fd594566c88e74fe293, delivery verified) and
acknowledged the decisions as settled the same day.

Built and verified the same day (README corrections 26–28):
the Lean composition's envelope and first-year bound are now
unconditional under Option A (audited Kernel/Tokenomics files
byte-identical; a poe-epoch battery pins the Rust close path);
finality certificates (poe-finality::cert) are emitted at
epoch close and verified evidence-only, with a Lean soundness
statement against Part B quorum intersection; the Merkle
companion root (poe-store::merkle) names births/deaths/
machines sections in each certificate and serves note proofs
over the control surface. Phase 3 was prepared as documents
plus a repo skeleton (standalone/): sealed Debian-derived
image, A/B updates under the poe-update-1 manifest, the
2-of-3 offline key ceremony specified — no key was generated
or held on this machine, and no image was built. The audit
engagement pack was refreshed (AUDIT_PACKAGE.md +
AUDIT_ENGAGEMENT.md) with the bounty figure and sign-off left
as owner blanks.

Full suite 104/104 (96 workspace + 8 poe-finality, scale
simnet in release; logs
~/workspace/poe-build-2026-11-11/test-logs-2026-11-17/).
node1 redeployed on the new binary (its unit had again been
wiped by a VM replacement; restored the standard way,
node2/node3 left retired, 6.5 GB drop-in re-added): KEYS
backend=file (software stub), machine unchanged
1123122162023658167, POEFIN4 resume, HOLDing round 3361,
RSS ~54 MB. Live probes of the new surface, verbatim:
`cert.latest` → error no_certificate ("this node has not
emitted a certificate yet"); `note.proof` → error no_close —
both expected: node1 has closed no epoch in this run, and
certificate emission remains simnet-proved, not yet
live-observed, until a canonical peer mesh exists again.
Railway remains on its fork lineage pending the bundle-URL
flip (owner's dashboard action, unchanged).

## Operations log — 2026-11-20: mesh re-drive, first live closes on the bounded-DAG binary, correction 35

Stood the local mesh back up (node1/2/3) to produce live
epoch closes and soak evidence. The mesh wedged at round
3361 (divergent reveal closes from the 2026-11-14
re-anchor); a night of diagnosis and fixes followed —
the full account is README correction 35. Headlines:
skip attestation was unreachable through the node wiring
(now fixed and live-proved: `NULL round=3446 closed
empty by skip attestation` on both live nodes); buffer
starvation in holds; serve starvation; the catch-up
orbit; subset/empty reveal closes; bundles silently
carrying post-sync-point finality (now truncated at
write time); the anchor exception keying on blocks
instead of reveals.

Two operator re-anchors were performed (the design's
stated recovery — final state never lost, unfinalized
tails discarded). Preserved on disk per node, not
deleted: finstate.bin.pre-anchor-2026-11-20 +
store.pre-anchor-2026-11-20 (first), then .held/.held2/
.held3 (node1), .diverged-, .forked-, .orbit-,
.forked2-, .forked3-2026-11-20 (later iterations), and
node2/node3's bundle.bin.polluted-2026-11-20 (the
bundles that carried round 3440's finality). The final
run synced all three nodes from ONE identical bundle
(node2's epoch-214 bundle, md5 1cef48288f58a5e85f517b266e99574c —
the copy already held as node1's bundle.bin) under
transient units poe-rec1/2/3, node1 deliberately NOT
peered to Railway for these runs.

Results: epochs 210–214 closed live with PRUNE + CERT
(epoch 210: PRUNE dropped=6268 retained=35, CERT
votes=2 announcements=8; certs on disk in node2/node3
certs/). Final run agreement, verified by finstate-dump
on all three: round 3440 NULL by 3/3 skip attestation,
round 3441 by 3/3 tally, no conflicting finality
anywhere. One liveness gap remains (node2's own reveal
missing from its round-3443 close; its committee view
differs by one member and the 3443 vote the other nodes
wait on was never cast). The mesh was stopped on
2026-11-20 ~04:52 +06 in that consistent state rather
than left to drift; restart is a finstate resume per
node (keys and bundles in place). Suite count on the
correction-35 binary: see the 2026-11-20 test logs under
~/workspace/poe-build-2026-11-11/test-logs-2026-11-20/.
Railway unchanged (bundle-URL flip still the owner's
dashboard action, rested).

## Ops entry 2026-11-20 (later) — correction 36: the 215 stall fixed, soak begins

Correction 35 was pushed first (main 933ba351 → 7ef0bfd6,
Railway redeploy accepted by the owners). The 215 fix
followed: in crates/poe-node/src/testnet.rs, the
settled-hold's reveal re-derive no longer abstains while
the node is observing (the exact suppression behind
node2's missing round-3443 reveal). Release build clean,
poe-node tests 10/10. The stalled states were preserved
as finstate.bin.pre-fix36-2026-11-20 /
store.pre-fix36-2026-11-20 and all three nodes were
re-anchored from the same identical epoch-214 bundle
(md5 1cef48288f58a5e85f517b266e99574c on all three) under
transient units poe-rec1/2/3, node1 not peered to
Railway. Result: epoch 215 closed on all three nodes
under one root (0c7d7e0dd068580b, CERT close_round=3455),
then 216 (6a7124fd87e0d7c1) and 217; cert-215.bin and
cert-216.bin on disk on all three; finstate dumps
identical in their finalized entries through round 3455;
round 3443 — the stalled round — finalized as block
2fbcb390d76de137 on all three. Minted unchanged
(300000000399999) throughout. The mesh was left running:
the Stage 2 soak starts from this verified state. No
PRUNE lines at the 215/216 closes: the prune call logs
only when it drops, and the 215 anchor round (3440)
finalized NULL, so there was no block anchor to prune
from; earlier live PRUNE lines stand at epochs 210–214.
