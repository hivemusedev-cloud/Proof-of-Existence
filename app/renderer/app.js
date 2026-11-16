// PoE Suite renderer. Everything it shows comes from the node
// through window.poe (the preload bridge) — protocol state only
// ever comes from the control endpoint's answers, never from
// the service's log output.

const $ = (sel) => document.querySelector(sel);

// Integers arrive as strings when they exceed Number's safe
// range (the main process quotes them); format either kind
// with thousands separators without losing digits.
function fmt(v) {
  if (v === null || v === undefined) return '—';
  const s = String(v);
  if (!/^-?\d+$/.test(s)) return s;
  return s.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}
function short(v) {
  const s = String(v ?? '');
  return s.length > 22 ? `${s.slice(0, 12)}…${s.slice(-6)}` : s;
}
function card(k, v) {
  return `<div class="card"><div class="k">${k}</div><div class="v">${v}</div></div>`;
}
function showMsg(el, envelope, okText) {
  if (envelope && envelope.ok) {
    el.className = 'msg';
    el.textContent = okText || '';
    return envelope.result;
  }
  const err = (envelope && envelope.error) || { code: 'error', message: 'no response' };
  el.className = 'msg' + (err.code === 'gated' ? ' gated' : ' err');
  el.textContent = `${err.code}: ${err.message}`;
  return null;
}

// -- navigation ---------------------------------------------------------------
document.querySelectorAll('nav button').forEach((b) => {
  b.addEventListener('click', () => {
    document.querySelectorAll('nav button').forEach((x) => x.classList.remove('active'));
    document.querySelectorAll('.view').forEach((x) => x.classList.remove('active'));
    b.classList.add('active');
    $(`#view-${b.dataset.view}`).classList.add('active');
    if (b.dataset.view === 'wallet') loadWallet();
    if (b.dataset.view === 'swap') loadV2();
    if (b.dataset.view === 'node') loadNodeView();
  });
});

// -- node state ---------------------------------------------------------------
function paintState(state, supervised) {
  const pill = $('#state-pill');
  pill.textContent = state;
  pill.className = `pill ${state}`;
  $('#state-note').textContent =
    state === 'adopted' ? 'Connected to a node this shell did not start.'
    : supervised ? 'Supervised by this shell.' : '';
}
window.poe.onState((s) => window.poe.nodeStatus().then((r) => paintState(s, r.supervised)));
window.poe.onLog((line) => {
  const pre = $('#log');
  pre.textContent += line + '\n';
  pre.scrollTop = pre.scrollHeight;
});

// -- overview -----------------------------------------------------------------
async function refreshStatus() {
  const r = await window.poe.call('status');
  const msg = $('#overview-msg');
  if (!r.ok) {
    msg.className = 'msg';
    msg.textContent = 'Waiting for the node service…';
    return;
  }
  msg.textContent = '';
  const s = r.result;
  $('#overview-grid').innerHTML = [
    card('Machine', `<span class="mono">${fmt(s.machine)}</span>`),
    card('Keys backend', s.keys_backend),
    card('Mainnet eligible', 'no (testnet profile)'),
    card('Joined', s.joined ? 'yes' : 'no'),
    card('Epoch', fmt(s.epoch)),
    card('Head round', fmt(s.head_round)),
    card('Next apply', fmt(s.next_apply)),
    card('Minted', fmt(s.minted)),
    card('Pending ops', fmt(s.pending_ops)),
    card('Containers held', fmt(s.containers)),
    card('V2 gate', s.v2_gate),
  ].join('');
}

// -- wallet -------------------------------------------------------------------
async function loadWallet() {
  const notes = await window.poe.call('wallet.notes');
  if (notes.ok) {
    const rows = notes.result.notes.map((n) =>
      `<tr><td>${fmt(n.value)}</td><td>${fmt(n.asset)}</td><td>${fmt(n.born)}</td>` +
      `<td class="mono">${short(n.cm)}</td><td class="mono">${short(n.nf)}</td></tr>`).join('');
    $('#notes').innerHTML =
      `<p class="note">Total live value: <b>${fmt(notes.result.total)}</b></p>` +
      (rows ? `<table><tr><th>Value</th><th>Asset</th><th>Born</th><th>cm</th><th>nf</th></tr>${rows}</table>`
            : '<p class="note">No live notes.</p>');
  }
  const conts = await window.poe.call('wallet.containers');
  if (conts.ok) {
    const list = conts.result.containers || conts.result || [];
    const rows = (Array.isArray(list) ? list : []).map((c) =>
      `<tr><td class="mono">${short(c.coin)}</td><td>${fmt(c.value)}</td><td>${fmt(c.shows_recorded ?? c.shows ?? '')}</td></tr>`).join('');
    $('#containers').innerHTML = rows
      ? `<table><tr><th>Coin</th><th>Value</th><th>Shows recorded</th></tr>${rows}</table>`
      : '<p class="note">No containers held.</p>';
  }
}

$('#import-btn').addEventListener('click', async () => {
  const file = await window.poe.pickFile();
  if (!file) return;
  const r = await window.poe.call('wallet.container.import', { path: file });
  showMsg($('#import-msg'), r, 'Container imported.');
  loadWallet();
});

$('#show-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const r = await window.poe.call('wallet.show', {
    coin: Number(f.get('coin')),
    challenge: Number(f.get('challenge')),
    counterparty: Number(f.get('counterparty') || 0),
  });
  const res = showMsg($('#show-msg'), r, '');
  if (res) $('#show-msg').textContent = `Show performed — response ${fmt(res.response)} (recorded in the container's show log).`;
});

$('#transfer-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  let ins, outs;
  try {
    ins = JSON.parse(f.get('ins') || '[]');
    outs = JSON.parse(f.get('outs') || '[]');
  } catch (err) {
    const el = $('#transfer-msg');
    el.className = 'msg err';
    el.textContent = `JSON parse error: ${err.message}`;
    return;
  }
  const r = await window.poe.call('wallet.transfer', { ins, outs });
  showMsg($('#transfer-msg'), r, 'Transfer queued — it drains into the next proposal this node makes, after re-validation.');
});

// -- swap & bridge --------------------------------------------------------------
async function loadV2() {
  const r = await window.poe.call('v2.state');
  if (!r.ok) return;
  const s = r.result;
  $('#v2-grid').innerHTML = [
    card('Spot', fmt(s.spot)),
    card('Pool X', fmt(s.pool_x)),
    card('Pool Y', fmt(s.pool_y)),
    card('Curve version', fmt(s.curve_version)),
    card('Gate', s.gate),
  ].join('');
}

$('#quote-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const r = await window.poe.call('v2.quote', {
    side: f.get('side'),
    amount: String(f.get('amount')),
  });
  const res = showMsg($('#quote-msg'), r, '');
  if (res) $('#quote-msg').textContent = `${res.side}: in ${fmt(res.in)} → out ${fmt(res.out)}`;
});

for (const [id, method] of [['#swap-btn', 'v2.swap'], ['#bridge-btn', 'v2.bridge']]) {
  $(id).addEventListener('click', async () => {
    const r = await window.poe.call(method, {});
    // Execution is gated by design; the refusal is a product
    // state to display, not a failure.
    showMsg($('#exec-msg'), r, 'Done.');
  });
}

// -- node view ------------------------------------------------------------------
async function loadNodeView() {
  const env = await window.poe.env();
  const st = await window.poe.nodeStatus();
  $('#node-grid').innerHTML = [
    card('Data directory', `<span class="mono">${env.dataDir}</span>`),
    card('Control endpoint', `<span class="mono">${env.endpoint}</span>`),
    card('Node binary', `<span class="mono">${env.binary}</span>`),
    card('Service state', `${st.state}${st.supervised ? ' (supervised)' : ''}`),
  ].join('');
  const logs = await window.poe.logs();
  $('#log').textContent = logs.join('\n') + '\n';
}

$('#start-btn').addEventListener('click', async () => { await window.poe.startNode(); loadNodeView(); });
$('#stop-btn').addEventListener('click', async () => { await window.poe.stopNode(); loadNodeView(); });

// -- boot -----------------------------------------------------------------------
window.poe.env().then(() => {
  window.poe.nodeStatus().then((r) => paintState(r.state, r.supervised));
  refreshStatus();
  setInterval(refreshStatus, 5000);
});
