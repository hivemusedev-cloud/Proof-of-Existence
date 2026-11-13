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
| Genesis time (t0) | 2026-11-13 20:52:00 Asia/Dhaka (+06) (unix `1794581520`) |
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
  --peer /ip4/104.29.200.165/tcp/41001/p2p/12D3KooWMTHxVwirHRgDskKvkSv12NgwVAtnitvwSBaoJVv3ataF
```

**If the chain is already running**, sync from a bundle published by
any running node (the bootstrap nodes serve theirs, see below), then
start with it:

```bash
curl -O http://104.29.200.165:4180/bundle.bin
./target/release/poe-node testnet \
  --dir ~/poe-testnet-node \
  --listen /ip4/0.0.0.0/tcp/41001 \
  --peer /ip4/104.29.200.165/tcp/41001/p2p/12D3KooWMTHxVwirHRgDskKvkSv12NgwVAtnitvwSBaoJVv3ataF \
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

- `/ip4/104.29.200.165/tcp/41001/p2p/12D3KooWMTHxVwirHRgDskKvkSv12NgwVAtnitvwSBaoJVv3ataF` (machine 3950040106910302592)
- `/ip4/104.29.200.165/tcp/41002/p2p/12D3KooWBhCgocWUu6UTiP97UTvmyiZQvqr7wxC9cbLpoXZkVnQi` (machine 11579431428148030288)
- `/ip4/104.29.200.165/tcp/41003/p2p/12D3KooWLWFD73oLwmRwbf2CEk2Q5xmfhDtTk2P8yXmxMBdnYaLQ` (machine 1357345935748043147)

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
- State sync is bundle-based (an epoch-boundary snapshot served as a
  file), not yet an in-protocol exchange.
- The launch operator's bootstrap nodes run on one VM behind NAT
  (no inbound reachability from the public internet — see Bootstrap
  nodes); if it is down, anyone can re-bootstrap a peering point
  from this spec — the chain is its nodes, not its first operator.
