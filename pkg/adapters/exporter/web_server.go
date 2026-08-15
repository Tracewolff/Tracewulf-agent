package exporter

import (
	"log"
	"net/http"
)

// SnapshotProvider is anything that can return the latest snapshot as JSON.
type SnapshotProvider interface {
	LatestJSON() []byte
}

const dashboardHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta charset="UTF-8">
<title>TraceWulf</title>
<style>
body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
h1 { color: #58a6ff; }
table { border-collapse: collapse; width: 100%; margin-top: 10px; }
th, td { border: 1px solid #30363d; padding: 6px 10px; text-align: left; font-size: 13px; }
th { background: #161b22; color: #58a6ff; }
.internal { color: #3fb950; }
.external { color: #f85149; }
#meta { color: #8b949e; margin-bottom: 10px; }
</style>
</head>
<body>
<h1>TraceWulf live network flows</h1>
<div id="meta">loading...</div>
<table>
<thead><tr><th>Flow</th><th>Class</th><th>Count</th><th>Last Seen</th></tr></thead>
<tbody id="rows"></tbody>
</table>
<script>
async function refresh() {
  const res = await fetch('/snapshot');
  const data = await res.json();
  document.getElementById('meta').textContent =
    'timestamp=' + data.timestamp + '  exec_events=' + data.exec_events + '  unique_flows=' + data.unique_flows;
  const rows = data.flows.map(f =>
    '<tr><td>' + f.flow + '</td><td class="' + f.class + '">' + f.class + '</td><td>' + f.count + '</td><td>' + f.last_seen + '</td></tr>'
  ).join('');
  document.getElementById('rows').innerHTML = rows;
}
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>`

// Start launches an HTTP server exposing the latest snapshot as JSON at
// /snapshot and a simple auto-refreshing dashboard at /.
func Start(addr string, stats SnapshotProvider) {
	mux := http.NewServeMux()

	mux.HandleFunc("/snapshot", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(stats.LatestJSON())
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
