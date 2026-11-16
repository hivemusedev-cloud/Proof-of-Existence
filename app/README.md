# PoE Suite — desktop shell (Electron)

The desktop app of the PoE OS suite (Phase 1, app-mode). Shell
technology: **Electron**, by the owner's decision (2026-11-16,
chosen over Tauri for the control it gives). The shell is a
window onto the user's own node service — it holds no protocol
state of its own.

## What it does

- Resolves the suite's data directory with the same rules as
  the node (`poe-node paths`; `POE_DIR` overrides) and
  supervises the node service: it spawns `poe-node testnet`
  against that directory (first run: `--sync-from` the bundle,
  per the APP_PACKAGING lifecycle), or **adopts** a node that
  is already running there — an adopted node is served, never
  killed by the shell.
- Readiness is the packaging contract: the node is "running"
  when its local control endpoint answers `status`. The shell
  never parses the service's output for state (the log view is
  for the user's eyes only).
- Every view talks to the node through the control endpoint
  only: Overview (status), Wallet (live notes, container
  import/list, offline shows, raw-mark transfers), Swap &
  Bridge (live quotes; execution shows the node's `gated`
  refusal as a product state), Node (service control + log).
- Key custody stays the node's business: the shell passes the
  environment through, so `POE_VAULT=keyring` selects the OS
  keyring backend exactly as on the command line. The renderer
  has no Node.js access (context isolation + sandbox); its
  only bridge is `preload.js`.

## Run it (development)

```sh
npm install
npm start            # uses ../target/release/poe-node
```

Useful environment: `POE_DIR` (data directory), `POE_NODE_BIN`
(node binary), `POE_BUNDLE_PATH` (first-run bundle),
`POE_VAULT` (`file` | `keyring`).

## Verify it (headless smoke)

```sh
POE_APP_SMOKE=1 xvfb-run -a npx electron --no-sandbox .
```

Smoke mode starts the node on the resolved data directory,
waits for readiness, exercises status / wallet / v2 verbs
through the same client the UI uses (including asserting the
`gated` refusal from `v2.swap`), saves a window screenshot to
`POE_APP_SMOKE_SHOT`, and exits 0/1. Verified on this machine
2026-11-16 against a fresh scratch node: all verbs answered,
quote for 1e18 → 99966677774, screenshot rendered live data.

## Not yet

Installers and signed binaries (electron-builder wiring is
the next packaging step), the Windows named-pipe client (the
pipe server itself is shell-stage work on the node side), and
macOS/Windows store vault backends. Testnet profile only —
the V2 gate and mainnet gates are the node's, and the shell
inherits them.
