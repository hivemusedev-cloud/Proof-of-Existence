# poe-testnet-1 — the standing falsifier bounties

The Proof of Existence design rests on claims that can be *falsified*.
Three of them are published here as standing bounties on
**poe-testnet-1**. They are the same three falsifiers the build flow
names (Step 12c). A bounty is claimed by *demonstrating the break
against the live testnet*, with evidence any node operator can
independently re-verify from the chain's own records — blocks, votes,
state roots, and the ledger state they commit to.

These bounties concern the testnet's operation of the protocol. A
break demonstrated only against a modified client, a private fork, or
a network nobody else can inspect does not qualify: the point is that
the *shared* chain's one law held or fell.

## F-Height — register one height twice

**The claim under test.** Under the kernel's one law, a claim is a
(side, height) pair: the first registration of a height stands, and a
second registration of the same height is evidence against its author
— never a second accepted claim. This covers coin spends (a note's
nullifier height) and, at the ordering layer, one block per
(machine, round).

**To claim:** produce two *accepted* claims on the same height in the
live testnet's finalized history — e.g. the same note spent in two
different finalized transfers, or two different blocks by one machine
in one round both treated as canonical by honest nodes. Show the
finalized blocks, the two claims, and a state root under which both
stand accepted.

**Not a break:** a second claim that exists as *evidence* (that is the
design working), a double-spend that succeeds only inside an unfinalized
fork, or anything on a chain whose genesis hash differs from the
published spec.

## F-Clone — two bodies, one identity, both earning

**The claim under test.** A machine is one attested device. Cloned key
material on two bodies cannot both earn: the second body's binding is
refused as a clone attempt, and if one identity ever acts from two
bodies in consensus (two proposals in a round, two votes for different
sides), the act is evidence and the identity is revoked.

**To claim:** run one device identity on two machines such that *both*
receive grant credit for the same epoch on the live testnet — shown
from the chain's own close records (the epoch's claimant set and the
vesting credit implied by them) — or both have votes counted toward
finality in the same round without the identity being revoked.

**Not a break:** two *different* identities earning (identities are
free on this testnet — its attestation root is public by design; the
claim under test is about *one* identity in two bodies), or a clone
that earns on a fork nobody finalized.

## F-First-Year — grants above the first-year envelope

**The claim under test.** Total grants minted in the first 52 closes
of the chain never exceed **520,200,000,000** — 0.052% of the 10^15
cap — under the frozen reference profile, whatever the join flood,
renewal pattern, or usage signal. (Proved for the kernel model in
Lean; the bounty tests the *running network* against it.)

**To claim:** let the testnet run (or drive it) through 52 closes and
produce the chain's state roots and close records showing cumulative
grants above 520,200,000,000 — where cumulative grants are the ledger's
minted total minus the genesis reserve note, read at the 52nd close.

**Not a break:** minted totals that count the reserve note, totals
from a chain with a different genesis hash, or a single close above
its per-epoch budget presented as the year total (the envelope is a
52-close bound; a per-epoch budget breach is a different, also
reportable, bug — file it the same way).

## How to claim

Open an issue in this repository titled with the falsifier
(`F-Height claim`, …) containing:

1. The chain's genesis hash and the epoch(s) / round(s) involved.
2. The evidence bundle: the finalized blocks (ids and encodings), the
   claims or close records, and the state roots they stand under.
3. A minimal reproduction: what you ran, in what order, against which
   bootstrap nodes.

A claim is adjudicated by re-verification: any operator must be able
to replay the evidence against an honest node and reach the same
conclusion. Claims that verify are acknowledged in this repository
with the evidence attached — the acknowledgement, the fix, and the
regression test become part of the chain's public record.

**Reward:** the falsifiers stand as the protocol's public challenge.
A monetary reward pool is a launch parameter the operator sets and
announces in this file; until an amount is published here, claims earn
the public acknowledgement and the fix credit above. (Testnet coins
themselves are worthless by definition and are never a reward.)

## Scope notes

- The testnet's attestation root is public (anyone can mint an
  identity). F-Clone is about one identity in two bodies, not about
  identity scarcity — see the exclusion there.
- Liveness failures (the chain stalls) are worth reporting as issues
  but are not one of the three falsifiers; the package states its
  liveness assumption (partial synchrony, honest supermajority) openly.
- The ZK binding layer's algebraic accumulator and the transport
  layer's session design carry their own stated review debts in the
  crate docs; breaks there should be filed as issues with the same
  evidence standard.
