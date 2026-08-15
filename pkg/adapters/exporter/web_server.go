package exporter

import (
	"log"
	"net/http"
)

type SnapshotProvider interface {
	LatestJSON() []byte
}

type HistoryProvider interface {
	HistoryJSON() []byte
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TraceWulf</title>
<style>
  :root {
    --bg:        #0a0e14;
    --panel:     #10151d;
    --panel-2:   #141a24;
    --border:    #1e2630;
    --text:      #e6e9ef;
    --text-dim:  #7d8590;
    --text-mute: #4b5563;
    --cyan:      #56d4dd;
    --amber:     #f0a75f;
    --red:       #ff6b6b;
    --green:     #3fb950;
    --mono: ui-monospace, 'JetBrains Mono', 'Fira Code', 'SFMono-Regular', Consolas, monospace;
  }
  * { box-sizing: border-box; }
  body {
    font-family: var(--mono);
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 28px 32px 60px;
    -webkit-font-smoothing: antialiased;
  }
  header { display: flex; align-items: baseline; justify-content: space-between; margin-bottom: 22px; flex-wrap: wrap; gap: 10px; }
  .brand { display: flex; align-items: center; gap: 10px; }
  .brand h1 { font-size: 20px; letter-spacing: 0.02em; margin: 0; color: var(--text); font-weight: 700; }
  .brand h1 span { color: var(--cyan); }
  .pulse {
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--cyan);
    box-shadow: 0 0 0 0 rgba(86,212,221,0.6);
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%   { box-shadow: 0 0 0 0 rgba(86,212,221,0.55); }
    70%  { box-shadow: 0 0 0 7px rgba(86,212,221,0); }
    100% { box-shadow: 0 0 0 0 rgba(86,212,221,0); }
  }
  #meta { color: var(--text-mute); font-size: 12px; }

  .section-label { font-size: 11px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.08em; margin: 22px 0 10px; }

  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-bottom: 8px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 14px 16px; }
  .card .label { font-size: 11px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 6px; }
  .card .value { font-size: 24px; font-weight: 700; color: var(--text); }
  .card .value.accent { color: var(--cyan); }
  .card .value.money { color: var(--green); }
  .card .sub { font-size: 11px; color: var(--text-mute); margin-top: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  .controls { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
  #search {
    flex: 1; max-width: 320px;
    background: var(--panel); border: 1px solid var(--border); border-radius: 5px;
    color: var(--text); font-family: var(--mono); font-size: 13px;
    padding: 7px 10px;
  }
  #search::placeholder { color: var(--text-mute); }
  #search:focus { outline: none; border-color: var(--cyan); }
  .hint { font-size: 11px; color: var(--text-mute); }

  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; margin-bottom: 4px; }
  table { border-collapse: collapse; width: 100%; }
  th, td { padding: 9px 14px; text-align: left; font-size: 13px; border-bottom: 1px solid var(--border); }
  th {
    background: var(--panel-2); color: var(--text-dim);
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600;
    cursor: pointer; user-select: none; white-space: nowrap;
  }
  th:hover { color: var(--text); }
  th.sorted { color: var(--cyan); }
  th .arrow { font-size: 9px; margin-left: 3px; opacity: 0.7; }
  tbody tr:hover { background: var(--panel-2); }
  tbody tr:last-child td { border-bottom: none; }

  .pill { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; }
  .pill.internal { background: rgba(86,212,221,0.12); color: var(--cyan); }
  .pill.external { background: rgba(255,107,107,0.12); color: var(--red); }
  .pill.unknown  { background: rgba(125,133,144,0.12); color: var(--text-dim); }
  .pill.crossaz  { background: rgba(240,167,95,0.14); color: var(--amber); }

  .bytes-cell { position: relative; min-width: 140px; }
  .bytes-bar {
    position: absolute; left: 0; top: 0; bottom: 0;
    background: linear-gradient(90deg, rgba(86,212,221,0.16), rgba(86,212,221,0.05));
    border-radius: 3px; z-index: 0;
  }
  .bytes-val { position: relative; z-index: 1; }

  .flow-col { color: var(--text); }
  .flow-col .arrow-sep { color: var(--text-mute); margin: 0 4px; }

  #empty { padding: 30px; text-align: center; color: var(--text-mute); font-size: 13px; display: none; }
</style>
</head>
<body>

<header>
  <div class="brand">
    <span class="pulse"></span>
    <h1>Trace<span>Wulf</span> — live network flows</h1>
  </div>
  <div id="meta">—</div>
</header>

<div class="section-label">This interval</div>
<div class="stats">
  <div class="card">
    <div class="label">Unique Flows</div>
    <div class="value" id="stat-flows">0</div>
  </div>
  <div class="card">
    <div class="label">Exec Events</div>
    <div class="value" id="stat-exec">0</div>
  </div>
  <div class="card">
    <div class="label">Total Traffic</div>
    <div class="value accent" id="stat-bytes">0 B</div>
  </div>
  <div class="card">
    <div class="label">Top Talker</div>
    <div class="value accent" id="stat-top" style="font-size:15px;">—</div>
    <div class="sub" id="stat-top-bytes"></div>
  </div>
</div>

<div class="section-label">Cumulative (since <span id="since-ts">—</span>)</div>
<div class="stats">
  <div class="card">
    <div class="label">Total Traffic (session)</div>
    <div class="value" id="hist-bytes">0 B</div>
  </div>
  <div class="card">
    <div class="label">Cross-AZ Traffic (session)</div>
    <div class="value" style="color:var(--amber)" id="hist-crossaz-bytes">0 B</div>
  </div>
  <div class="card">
    <div class="label">Estimated Cross-AZ Cost (session)</div>
    <div class="value money" id="hist-cost">$0.00</div>
    <div class="sub" id="hist-rate"></div>
  </div>
</div>

<div class="controls">
  <input id="search" type="text" placeholder="Filter by pod, service, ip, port..." />
  <span class="hint">click a column header to sort</span>
</div>

<div class="panel">
  <table>
    <thead>
      <tr>
        <th data-key="flow">Flow<span class="arrow"></span></th>
        <th data-key="class">Class<span class="arrow"></span></th>
        <th data-key="count">Count<span class="arrow"></span></th>
        <th data-key="bytes">Bytes<span class="arrow"></span></th>
        <th data-key="cost_usd">Cost<span class="arrow"></span></th>
        <th data-key="last_seen">Last Seen<span class="arrow"></span></th>
      </tr>
    </thead>
    <tbody id="rows"></tbody>
  </table>
  <div id="empty">no flows match your filter</div>
</div>

<div class="section-label">Recent intervals (cost trend)</div>
<div class="panel">
  <table>
    <thead>
      <tr><th>Time</th><th>Bytes</th><th>Cross-AZ Bytes</th><th>Cost</th></tr>
    </thead>
    <tbody id="trend-rows"></tbody>
  </table>
</div>

<script>
let latest = { flows: [] };
let sortKey = 'bytes';
let sortDir = -1;

function formatBytes(n) {
  n = n || 0;
  if (n < 1024) return n + ' B';
  if (n < 1024*1024) return (n/1024).toFixed(1) + ' KB';
  if (n < 1024*1024*1024) return (n/1024/1024).toFixed(2) + ' MB';
  return (n/1024/1024/1024).toFixed(2) + ' GB';
}

function formatUSD(n) {
  n = n || 0;
  if (n === 0) return '$0.00';
  if (n < 0.01) return '$' + n.toFixed(8);
  return '$' + n.toFixed(4);
}

function pillClass(c) {
  if (c === 'internal' || c === 'external') return c;
  return 'unknown';
}

function render() {
  const q = document.getElementById('search').value.trim().toLowerCase();
  let flows = latest.flows.slice();

  if (q) {
    flows = flows.filter(f => f.flow.toLowerCase().includes(q) || f.class.toLowerCase().includes(q));
  }

  flows.sort((a, b) => {
    let av = a[sortKey], bv = b[sortKey];
    if (typeof av === 'string') { av = av.toLowerCase(); bv = bv.toLowerCase(); }
    if (av < bv) return -1 * sortDir;
    if (av > bv) return 1 * sortDir;
    return 0;
  });

  const maxBytes = Math.max(1, ...flows.map(f => f.bytes || 0));

  document.getElementById('rows').innerHTML = flows.map(f => {
    const pct = Math.min(100, ((f.bytes || 0) / maxBytes) * 100);
    const parts = f.flow.split(' -> ');
    const flowHTML = parts.length === 2
      ? parts[0] + '<span class="arrow-sep">&rarr;</span>' + parts[1]
      : f.flow;
    const costHTML = f.cross_az
      ? '<span class="pill crossaz">' + formatUSD(f.cost_usd) + '</span>'
      : '<span style="color:var(--text-mute)">—</span>';
    return '<tr>' +
      '<td class="flow-col">' + flowHTML + '</td>' +
      '<td><span class="pill ' + pillClass(f.class) + '">' + f.class + '</span></td>' +
      '<td>' + f.count + '</td>' +
      '<td class="bytes-cell"><span class="bytes-bar" style="width:' + pct + '%"></span><span class="bytes-val">' + formatBytes(f.bytes) + '</span></td>' +
      '<td>' + costHTML + '</td>' +
      '<td>' + f.last_seen + '</td>' +
      '</tr>';
  }).join('');

  document.getElementById('empty').style.display = flows.length === 0 ? 'block' : 'none';

  document.querySelectorAll('th[data-key]').forEach(th => {
    th.classList.toggle('sorted', th.dataset.key === sortKey);
    const arrow = th.querySelector('.arrow');
    if (arrow) arrow.textContent = th.dataset.key === sortKey ? (sortDir === 1 ? '▲' : '▼') : '';
  });
}

function updateStats(data) {
  document.getElementById('stat-flows').textContent = data.unique_flows;
  document.getElementById('stat-exec').textContent = data.exec_events;
  document.getElementById('stat-bytes').textContent = formatBytes(data.total_bytes);

  const top = data.flows.slice().sort((a, b) => (b.bytes||0) - (a.bytes||0))[0];
  if (top) {
    document.getElementById('stat-top').textContent = top.flow;
    document.getElementById('stat-top-bytes').textContent = formatBytes(top.bytes) + ' transferred';
  } else {
    document.getElementById('stat-top').textContent = '—';
    document.getElementById('stat-top-bytes').textContent = '';
  }
}

function updateHistory(h) {
  document.getElementById('since-ts').textContent = h.since;
  document.getElementById('hist-bytes').textContent = formatBytes(h.cumulative_bytes);
  document.getElementById('hist-crossaz-bytes').textContent = formatBytes(h.cumulative_cross_az_bytes);
  document.getElementById('hist-cost').textContent = formatUSD(h.cumulative_cost_usd);

  const rows = h.intervals.slice().reverse().slice(0, 20).map(iv => {
    return '<tr>' +
      '<td>' + iv.timestamp + '</td>' +
      '<td>' + formatBytes(iv.total_bytes) + '</td>' +
      '<td style="color:var(--amber)">' + formatBytes(iv.cross_az_bytes) + '</td>' +
      '<td class="money" style="color:var(--green)">' + formatUSD(iv.total_cost_usd) + '</td>' +
      '</tr>';
  }).join('');
  document.getElementById('trend-rows').innerHTML = rows || '<tr><td colspan="4" style="color:var(--text-mute)">no intervals recorded yet</td></tr>';
}

async function refresh() {
  const [snapRes, histRes] = await Promise.all([
    fetch('/snapshot'),
    fetch('/history'),
  ]);
  const data = await snapRes.json();
  const hist = await histRes.json();

  latest = data;
  document.getElementById('meta').textContent =
    'last refreshed ' + data.timestamp + '  ·  cost model: $' + data.cost_per_gb_usd + '/GB cross-AZ';
  updateStats(data);
  updateHistory(hist);
  render();
}

document.querySelectorAll('th[data-key]').forEach(th => {
  th.addEventListener('click', () => {
    const key = th.dataset.key;
    if (sortKey === key) { sortDir *= -1; }
    else { sortKey = key; sortDir = -1; }
    render();
  });
});

document.getElementById('search').addEventListener('input', render);

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>`

// Start launches an HTTP server exposing the latest snapshot at /snapshot,
// cumulative history at /history, and a live dashboard at /.
func Start(addr string, stats SnapshotProvider, history HistoryProvider) {
	mux := http.NewServeMux()

	mux.HandleFunc("/snapshot", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(stats.LatestJSON())
	})

	mux.HandleFunc("/history", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(history.HistoryJSON())
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(dashboardHTML))
	})

	log.Printf("TraceWulf dashboard listening on http://%s", addr)
	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Printf("dashboard server error: %v", err)
		}
	}()
}
