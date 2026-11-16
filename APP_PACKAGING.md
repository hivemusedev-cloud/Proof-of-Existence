# PoE suite — app packaging contract (Phase 1)

How the desktop suite (app-mode of the adopted PoE OS model) is
put together, written before the shell so the shell — whichever
technology the owners choose — has fixed conventions to build
against instead of inventing its own. Everything here is
shell-independent; the shell renders UI and calls these seams,
it does not redefine them.

## The pieces

| Piece | What it is | Status |
|---|---|---|
| Node service | `poe-node testnet --dir <data dir>` — the same binary as the testnet's | exists |
| Control endpoint | Local-only IPC the shell talks to: status, wallet, poe-v2 quotes (execution gated) | exists (Phase 0 item 3) |
| Key custody | `KeyVault` backends: file stub; OS keyring (Secret Service) via `POE_VAULT` | exists (Phase 0 item 2, Phase 1) |
| Data-dir resolution | `poe-node paths` | exists (this phase) |
| Service definition | `poe-node service-unit` (systemd user unit, Linux) | exists (this phase) |
| Shell | The desktop UI over the control endpoint — **Electron** (owner's decision, 2026-11-16, over the Tauri recommendation, for the control it gives) | v1 built in `app/` — supervision, adoption, all control verbs wired; headless smoke verified |
| Installers / signing | Per-OS packages and signed binaries | **Linux done 2026-11-16:** AppImage + .deb via electron-builder, carrying the node binary + bundle as packaged resources; extracted-AppImage smoke run verified end-to-end. Unsigned (owner's signing key not configured). Windows/macOS packages later in Phase 1 |

## Data directory

One data directory per node identity. Resolution:
`--dir` for a run always wins; the app-mode default is
`poe-node paths`:

- **Linux:** `$XDG_DATA_HOME/poe-node`, else `~/.local/share/poe-node`
- **macOS:** `~/Library/Application Support/PoE Node`
- **Windows:** `%LOCALAPPDATA%\PoE Node`
- `POE_DIR` overrides the default (portable installs, tests).

The directory holds the store, the finstate, the epoch bundle,
wallet containers, and (file backend only) the key files. Its
on-disk formats are versioned (`POEFIN4`, `POEBNDL2`) and an
unreadable finstate degrades to the epoch bundle by design —
an app update never strands a node's state.

## Lifecycle

1. **First run.** The shell (or installer) creates the data
   directory, then starts the node with `--sync-from <bundle>`
   or the bundle URL arrangement the deployment uses; the node
   refuses a fresh start with no state and no bundle — that
   refusal is the correct first-run signal, not an error path.
2. **Start.** Spawn the node against the data directory, or
   install the generated user-service unit and let systemd
   supervise the identical command line.
3. **Readiness.** The node is up when the control endpoint
   answers `status`. The shell must not parse the node's
   stdout for state; the endpoint is the contract.
4. **Stop.** Terminate the process. State is written
   incrementally (finstate after every vote cast, bundle at
   every epoch close); a hard kill loses nothing finalized.
5. **Restart.** Plain start. The node resumes from its
   finstate, else its bundle, else refuses — in that order,
   by itself.
6. **Update.** Replace the binary; start. Format versions are
   read compatibly or degrade one step (above), never silently
   corrupt.

## Control endpoint

- **Unix:** `<data dir>/control.sock`, mode 0600, one JSON
  object per line (see `control.rs` for the verb set).
- **Windows:** the named pipe `\\.\pipe\poe-node-<dirname>` —
  the name is fixed now (`poe-node paths` prints it); the pipe
  *server* is Phase 1 shell-stage work, stated as such in the
  control surface's own docs.
- The endpoint is local-only by design: no listener, no
  network surface, the same trust boundary as the key files.

## Key custody in app-mode

`POE_VAULT` selects the backend, the node logs its choice at
startup (`KEYS backend=… mainnet_eligible=…`), and an unknown
or unavailable backend is fatal — never a silent downgrade.

- `file` (default): the software stub; keys as files in the
  data directory. Dev/testnet.
- `keyring`: the OS keyring (freedesktop Secret Service on
  Linux today; the vault is named after the data directory).
  Secrets are encrypted at rest under the user's login. This
  is a **different identity** from the same directory's file
  keys — switching backends is a migration (a new machine
  identity joins afresh), and the app must present it that way.
- Neither backend is mainnet-eligible; a mainnet-profile build
  refuses both. Hardware custody is a later phase's backend
  behind the same trait.

## What the shell owes the contract

- Resolve paths through `poe-node paths` (or the identical
  rules), never hardcode them.
- Treat `status` over the control endpoint as the only state
  source; treat the V2 gate's `gated` error as a product state
  to display, not a failure.
- Present backend choice and migration honestly (above).
- Voice, if any, is query-only (flag 3): it reads through the
  same endpoint and never reaches a signing path — the
  endpoint's verb set has no voice-reachable signer by design.
