# Verifying PoE Suite on Windows — a walkthrough for HiveDevs

Everything below runs on **your Windows machine**. The Linux
side built and cross-checked all of it; the steps marked
**[you verify]** are the ones only a real Windows box can
prove. Work top to bottom; each step says what you should
see and what to send back if it differs.

## What you are verifying

1. The packaged Windows app (installer or portable) starts
   its bundled node service and talks to it over the new
   **named-pipe** control surface.
2. `poe-node.exe ctl` works against that pipe.
3. The **DPAPI** vault backend (`POE_VAULT=dpapi`) creates
   and reloads an identity.
4. Optionally: the app *adopting* a node you started
   yourself from a command line.

## Before you start — your old node directory

Your existing Windows node data (from the issue #1 runs) is
on the **fork lineage** — it can never rejoin the canonical
chain, and nothing below touches it. The app uses a **fresh**
data directory by default (`%LOCALAPPDATA%\PoE Node`), which
means a **new machine identity**. That is what we want for
this verification. (If you later want your old machine id
`6000435601674731658` in the app, copy only the four key
files — `device.key`, `ticket.seed`, `xmss.key`, `peer.key`
— into a fresh directory; never copy the old store.)

## Step 1 — Install

You have two files (in `app/dist/` on the Linux side; get
them onto the Windows machine by whatever route you like):

- `PoE Suite Setup 0.1.0.exe` — the NSIS installer
  (per-user, no admin needed), or
- `PoE Suite 0.1.0.exe` — the portable build, no install.

The packages are **unsigned**, so Windows SmartScreen will
warn ("Windows protected your PC") — click **More info →
Run anyway**. Signing needs a code-signing certificate,
which is a later step.

## Step 2 — First launch **[you verify]**

Launch **PoE Suite**. What should happen:

- A window opens with the Overview view and the node state
  pill (bottom left) showing **starting**, then **running**
  within a few minutes. The first start is slow — the node
  generates a fresh XMSS identity (minutes of CPU, silent
  by design) and syncs the bundled epoch-209 bundle.
- Overview then shows: a new **Machine** id, **Keys
  backend** `file (software stub)`, **Epoch 210**, **Head
  round 3,360**, **Minted 300,000,000,399,999**, **V2 gate
  closed**.
- The Node view shows the service log, including
  `CONTROL listening on \\.\pipe\poe-node-PoE Node (local only)`.

Send back: a screenshot of the Overview once it says
**running**, plus anything that looks different from the
above.

## Step 3 — The pipe and `ctl` **[you verify]**

Open PowerShell in the install directory (the folder with
`resources\bin\poe-node.exe` under it; for the portable
build, the folder the exe extracted to — or point at any
copy of `poe-node.exe`):

```powershell
.\poe-node.exe ctl --dir "$env:LOCALAPPDATA\PoE Node" status
.\poe-node.exe ctl --dir "$env:LOCALAPPDATA\PoE Node" v2.quote '{"side":"buy","amount":"1000000000000000000"}'
```

Expected: `status` prints the same machine/epoch/minted as
the app shows; the quote prints `"out":99966677774`.

## Step 4 — DPAPI vault **[you verify]**

This proves the Windows key store. It uses a **separate
scratch directory** so your app data is untouched:

```powershell
mkdir $env:TEMP\poe-dpapi-test
$env:POE_VAULT = "dpapi"
.\poe-node.exe testnet --dir $env:TEMP\poe-dpapi-test --sync-from .\bundle-copy.bin --rounds 2
```

(For `--sync-from`, copy `bundle.bin` from the repo's
`testnet/` folder, or skip `--sync-from` and let it refuse
the fresh start — the KEYS line prints before that point
either way; simpler: point it at the bundle inside the
install, `resources\bundle.bin`.)

Expected, in the output:

- `KEYS backend=Windows DPAPI mainnet_eligible=false`
- A `dpapi\` folder appears inside the scratch directory
  holding `device.key`, `ticket.seed`, `xmss.key` — open
  one in Notepad: it must be **binary**, not hex text (that
  is the DPAPI protection).
- Run the same command a second time: the **same** machine
  id prints (the identity reloaded from the protected
  blobs).

Then try the custody property: copy the scratch directory
to a *different Windows user account* (or another machine)
and run it there — DPAPI must refuse, with a
`CryptUnprotectData failed` error and no fallback. That
refusal is the feature working.

Clean up: `Remove-Item -Recurse $env:TEMP\poe-dpapi-test`
and `Remove-Item Env:POE_VAULT`.

## Step 5 — Adoption (optional) **[you verify]**

Start a node yourself in PowerShell
(`.\poe-node.exe testnet --dir <some dir>`), wait for its
`CONTROL listening` line, then launch the app with the same
data directory (set `POE_DIR` to that dir before launching,
or just note the app uses its default dir — for this test
set `$env:POE_DIR` and launch from the same shell). The
pill should read **adopted**, the views should work, and
closing the app must **not** stop your command-line node.

## What "done" looks like

Steps 2–4 passing means Phase 1's Windows side is real:
pipe transport, packaged supervision, and DPAPI custody,
all on the machine they were built for. Anything that
fails, send me the exact output or screenshot — the fix
loop is: I patch, cross-build, and send you a fresh
`poe-node.exe` / package; nothing needs this Linux box to
be right about Windows twice.

## Known limits (by design, not failures)

- **Unsigned packages** — SmartScreen warning until a
  signing certificate exists.
- **Testnet profile only** — V2 execution stays gated;
  the app shows the refusal, correctly.
- The node still needs a **peer network** to advance past
  epoch 210: alone, it holds at round 3,361. That is the
  liveness rule, not a Windows problem.
