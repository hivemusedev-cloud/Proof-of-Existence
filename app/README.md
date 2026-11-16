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
`POE_VAULT` (`file` | `keyring` | `dpapi` on Windows |
`keychain` on macOS).

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

## Linux packages

```sh
npm run dist          # AppImage + .deb into dist/
npm run dist:appimage # just the AppImage
npm run dist:deb      # just the .deb
```

The packages carry the node service with them: electron-
builder places the release `poe-node` binary at
`resources/bin/poe-node` and the testnet bundle at
`resources/bundle.bin`, which is exactly where the shell
looks (see `nodeBinary()` / `bundlePath()` in main.js) — an
installed copy needs nothing else from this repo. Built and
verified 2026-11-16: `PoE Suite-0.1.0.AppImage` (109 MB) and
`poe-suite_0.1.0_amd64.deb` (75 MB); the AppImage was
extracted and run in smoke mode against a fresh data
directory — it started its bundled node, synced from its
bundled bundle, and every control verb answered. The
packages are **unsigned**: signing needs the owner's key
(GPG for the .deb; AppImage signing is optional), and no key
is configured in this repo.

## Windows package

```sh
npm run dist:win      # NSIS installer + portable .exe into dist/
```

Built with `build-win.json`: the node service is the
cross-built `../target/x86_64-pc-windows-gnu/release/
poe-node.exe`, placed at `resources/bin/poe-node.exe` with
the same bundled testnet bundle. The shell's control client
speaks to the node's Windows named pipe
(`\\.\pipe\poe-node-<dirname>`) — Node's `net` module treats
a pipe path as the endpoint, so the protocol and client code
are the same as on Unix. A portable executable was built and
verified on this host 2026-11-17 (the NSIS installer needs a
32-bit Wine on the Linux build host); the owner's on-device
verification steps are in `WINDOWS_WALKTHROUGH.md`. The
package is **unsigned** (no owner's certificate configured),
so Windows SmartScreen will ask on first run.

## Not yet

The macOS package (needs a Mac to build) and signed binaries
(owner's signing keys). Testnet profile only — the V2 gate
and mainnet gates are the node's, and the shell inherits
them.
