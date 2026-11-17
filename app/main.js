// PoE suite shell — Electron main process (PoE OS Phase 1).
//
// The shell's whole job, per APP_PACKAGING.md: resolve the data
// directory, supervise the node service (spawn it, or adopt one
// already running), wait until the control endpoint answers
// `status`, and talk to the node ONLY through that endpoint.
// The renderer gets a narrow bridge (preload.js); it never
// touches the socket, the filesystem, or the child process.
//
// Shell technology: Electron, by the owner's decision
// (2026-11-16) — chosen over Tauri for the control it gives.

const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const { spawn } = require('child_process');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');

// ---------------------------------------------------------------------------
// Environment resolution — the identical rules to the node's own
// appenv.rs (APP_PACKAGING.md allows the mirror; `poe-node paths`
// prints the same values). POE_DIR overrides, as there.

function dataDir() {
  if (process.env.POE_DIR) return process.env.POE_DIR;
  if (process.platform === 'darwin') {
    return path.join(os.homedir(), 'Library', 'Application Support', 'PoE Node');
  }
  if (process.platform === 'win32') {
    return path.join(process.env.LOCALAPPDATA || process.env.APPDATA || '', 'PoE Node');
  }
  if (process.env.XDG_DATA_HOME) return path.join(process.env.XDG_DATA_HOME, 'poe-node');
  return path.join(os.homedir(), '.local', 'share', 'poe-node');
}

function controlEndpoint(dir) {
  if (process.platform === 'win32') {
    return `\\\\.\\pipe\\poe-node-${path.basename(dir) || 'node'}`;
  }
  return path.join(dir, 'control.sock');
}

// The node binary: an explicit override, then the packaged
// sidecar location, then (development) this repo's release
// build next to the app/ directory.
function nodeBinary() {
  if (process.env.POE_NODE_BIN) return process.env.POE_NODE_BIN;
  const exe = process.platform === 'win32' ? 'poe-node.exe' : 'poe-node';
  const packaged = path.join(process.resourcesPath || '', 'bin', exe);
  if (process.resourcesPath && fs.existsSync(packaged)) return packaged;
  return path.join(__dirname, '..', 'target', 'release', exe);
}

// The first-run bundle (APP_PACKAGING lifecycle step 1): an
// explicit path, else the repo's published testnet bundle in a
// development checkout.
function bundlePath() {
  if (process.env.POE_BUNDLE_PATH) return process.env.POE_BUNDLE_PATH;
  const packaged = path.join(process.resourcesPath || '', 'bundle.bin');
  if (process.resourcesPath && fs.existsSync(packaged)) return packaged;
  const dev = path.join(__dirname, '..', 'testnet', 'bundle.bin');
  return fs.existsSync(dev) ? dev : null;
}

const DIR = dataDir();
const ENDPOINT = controlEndpoint(DIR);

// ---------------------------------------------------------------------------
// Control client — one JSON object per line over the local
// endpoint, exactly the `poe-node ctl` protocol. Integers with
// 16+ digits (machine ids, pool reserves) are quoted before
// parsing: they exceed Number.MAX_SAFE_INTEGER and JSON.parse
// would silently round them.

function parseResponse(line) {
  const safe = line.replace(/:(\d{16,})([,}])/g, ':"$1"$2');
  return JSON.parse(safe);
}

function ctlOnce(method, params, attemptTimeoutMs) {
  return new Promise((resolve, reject) => {
    // Node's net module speaks both transports by path: a
    // Unix socket file here, a Windows named pipe
    // (\\.\pipe\...) on win32 — same JSON-lines protocol.
    const conn = net.createConnection(ENDPOINT);
    let buf = '';
    const timer = setTimeout(() => {
      conn.destroy();
      const e = new Error(`control call ${method} timed out`);
      e.code = 'POE_CTL_TIMEOUT';
      reject(e);
    }, attemptTimeoutMs);
    conn.on('connect', () => {
      conn.write(JSON.stringify({ method, params }) + '\n');
    });
    conn.on('data', (d) => {
      buf += d.toString('utf8');
      const nl = buf.indexOf('\n');
      if (nl >= 0) {
        clearTimeout(timer);
        conn.end();
        try {
          resolve(parseResponse(buf.slice(0, nl)));
        } catch (e) {
          reject(e);
        }
      }
    });
    conn.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

// One control call, hardened 2026-11-17 after a field report: on
// Windows a connect can fail transiently while the node's pipe
// instance is between clients or not yet created (ENOENT), or the
// pipe can break mid-connect (EPIPE/ECONNRESET). A single attempt
// turned those into a permanent-looking "unreachable" in the UI
// while the node was healthy. Transient failures now retry with a
// short backoff until the call's overall deadline; the last error
// is what surfaces if the deadline passes.
async function ctl(method, params = {}, timeoutMs = 15000) {
  const TRANSIENT = new Set(['ENOENT', 'EPIPE', 'ECONNRESET', 'ECONNREFUSED', 'POE_CTL_TIMEOUT']);
  const deadline = Date.now() + timeoutMs;
  let lastErr = null;
  for (;;) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw lastErr || new Error(`control call ${method} timed out`);
    try {
      return await ctlOnce(method, params, Math.min(remaining, 5000));
    } catch (e) {
      lastErr = e;
      if (!TRANSIENT.has(e.code)) throw e;
      const left = deadline - Date.now();
      if (left <= 0) throw e;
      await new Promise((r) => setTimeout(r, Math.min(600, left)));
    }
  }
}

async function nodeAnswers() {
  try {
    const r = await ctl('status', {}, 3000);
    return r.ok === true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Node supervision.

let child = null;
let nodeState = 'stopped'; // stopped | starting | running | adopted | error
const logBuf = [];
let win = null;

function pushLog(line) {
  logBuf.push(line);
  if (logBuf.length > 300) logBuf.splice(0, logBuf.length - 300);
  if (win && !win.isDestroyed()) win.webContents.send('node-log', line);
}

function setState(s) {
  nodeState = s;
  if (win && !win.isDestroyed()) win.webContents.send('node-state', s);
}

async function startNode() {
  if (child) return;
  if (await nodeAnswers()) {
    setState('adopted'); // a node we did not spawn: serve it, never kill it
    return;
  }
  fs.mkdirSync(DIR, { recursive: true });
  const args = ['testnet', '--dir', DIR];
  const firstRun = !fs.existsSync(path.join(DIR, 'store'));
  const bundle = firstRun ? bundlePath() : null;
  if (firstRun && bundle) args.push('--sync-from', bundle);
  pushLog(`[shell] starting ${nodeBinary()} ${args.join(' ')}`);
  setState('starting');
  child = spawn(nodeBinary(), args, { env: process.env });
  child.stdout.on('data', (d) => d.toString().split('\n').filter(Boolean).forEach(pushLog));
  child.stderr.on('data', (d) => d.toString().split('\n').filter(Boolean).forEach(pushLog));
  child.on('exit', (code) => {
    pushLog(`[shell] node exited (code ${code})`);
    child = null;
    setState(code === 0 ? 'stopped' : 'error');
  });
  // Readiness is the contract: the endpoint answering `status`,
  // not anything the process prints. A fresh identity's key
  // generation takes minutes; allow for it.
  const deadline = Date.now() + 10 * 60 * 1000;
  while (Date.now() < deadline) {
    if (!child) return; // exited while starting; state already set
    if (await nodeAnswers()) {
      setState('running');
      return;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  pushLog('[shell] node did not answer status within 10 minutes');
  setState('error');
}

function stopNode() {
  if (child) {
    child.kill('SIGTERM');
    // state flips in the exit handler
  }
}

// ---------------------------------------------------------------------------
// IPC bridge (preload exposes this as window.poe).

ipcMain.handle('env', () => ({
  dataDir: DIR,
  endpoint: ENDPOINT,
  binary: nodeBinary(),
  platform: process.platform,
}));
ipcMain.handle('node-status', () => ({ state: nodeState, supervised: child !== null }));
ipcMain.handle('node-start', async () => { await startNode(); return { state: nodeState }; });
ipcMain.handle('node-stop', () => { stopNode(); return { state: nodeState }; });
ipcMain.handle('node-logs', () => logBuf.slice());
ipcMain.handle('call', async (_e, method, params) => {
  try {
    return await ctl(method, params || {});
  } catch (e) {
    return { ok: false, error: { code: 'unreachable', message: String(e.message || e) } };
  }
});
ipcMain.handle('pick-file', async () => {
  const r = await dialog.showOpenDialog(win, {
    title: 'Import an Existence Container (.poec)',
    properties: ['openFile'],
  });
  return r.canceled ? null : r.filePaths[0];
});

// ---------------------------------------------------------------------------
// Window + lifecycle.

async function createWindow() {
  win = new BrowserWindow({
    width: 1120,
    height: 780,
    backgroundColor: '#101418',
    title: 'PoE Suite',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  await win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

app.whenReady().then(async () => {
  await createWindow();
  startNode(); // the suite supervises its service from launch
  if (process.env.POE_APP_SMOKE === '1') {
    runSmoke().catch((e) => {
      console.log(`SMOKE FAIL ${e && e.stack ? e.stack : e}`);
      app.exit(1);
    });
  }
});

app.on('window-all-closed', () => {
  stopNode();
  app.quit();
});

app.on('before-quit', stopNode);

// ---------------------------------------------------------------------------
// Smoke mode (development verification): wait for readiness,
// exercise every verb through the same client the UI uses, dump
// the window to a PNG, and exit 0/1. Run it headless under
// Xvfb:  POE_APP_SMOKE=1 xvfb-run -a npm run smoke

async function runSmoke() {
  const deadline = Date.now() + 10 * 60 * 1000;
  while (nodeState !== 'running' && nodeState !== 'adopted') {
    if (Date.now() > deadline || nodeState === 'error') {
      throw new Error(`node never became ready (state=${nodeState})`);
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  const calls = [
    ['status', {}],
    ['wallet.notes', {}],
    ['wallet.containers', {}],
    ['v2.state', {}],
    ['v2.quote', { side: 'buy', amount: '1000000000000000000' }],
    ['v2.swap', {}], // must come back as the gated refusal
  ];
  for (const [method, params] of calls) {
    const r = await ctl(method, params);
    console.log(`SMOKE ${method} ${JSON.stringify(r)}`);
    if (method !== 'v2.swap' && r.ok !== true) {
      throw new Error(`${method} did not return ok`);
    }
    if (method === 'v2.swap' && (r.ok !== false || !r.error || r.error.code !== 'gated')) {
      throw new Error('v2.swap did not return the gated refusal');
    }
  }
  const shot = process.env.POE_APP_SMOKE_SHOT || path.join(os.tmpdir(), 'poe-suite-smoke.png');
  await new Promise((r) => setTimeout(r, 1500)); // let the renderer paint live data
  const image = await win.webContents.capturePage();
  fs.writeFileSync(shot, image.toPNG());
  console.log(`SMOKE screenshot ${shot}`);
  console.log('SMOKE DONE');
  app.exit(0);
}
