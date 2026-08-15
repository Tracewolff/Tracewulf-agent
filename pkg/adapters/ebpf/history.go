package ebpf

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// IntervalRecord is what gets persisted to disk per reporting interval —
// aggregate numbers only, not per-flow detail, to keep the history file
// and in-memory ring buffer small.
type IntervalRecord struct {
	Timestamp    string  `json:"timestamp"`
	TotalBytes   uint64  `json:"total_bytes"`
	CrossAZBytes uint64  `json:"cross_az_bytes"`
	TotalCostUSD float64 `json:"total_cost_usd"`
	ExecEvents   uint64  `json:"exec_events"`
	UniqueFlows  int     `json:"unique_flows"`
}

type HistorySummary struct {
	Since             string           `json:"since"`
	CumulativeBytes   uint64           `json:"cumulative_bytes"`
	CumulativeCrossAZ uint64           `json:"cumulative_cross_az_bytes"`
	CumulativeCostUSD float64          `json:"cumulative_cost_usd"`
	Intervals         []IntervalRecord `json:"intervals"`
}

// historyRingCap bounds in-memory history to 1 hour at a 10s interval,
// so RAM stays flat regardless of uptime. The file on disk keeps the
// full history; only the ring buffer (for the dashboard's recent view)
// is capped.
const historyRingCap = 360

type HistoryStore struct {
	mu         sync.Mutex
	file       *os.File
	ring       []IntervalRecord
	cumBytes   uint64
	cumCrossAZ uint64
	cumCost    float64
	since      string
}

func defaultHistoryPath() string {
	if v := os.Getenv("TRACEWULF_HISTORY_FILE"); v != "" {
		return v
	}
	return "tracewulf-history.jsonl"
}

// NewHistoryStore opens (or creates) the history file, replays existing
// entries to reconstruct cumulative totals, then keeps the file open for
// append-only writes. Malformed lines are skipped rather than failing
// startup — a corrupted tail shouldn't take down the daemon.
func NewHistoryStore() (*HistoryStore, error) {
	path := defaultHistoryPath()
	h := &HistoryStore{}

	if existing, err := os.Open(path); err == nil {
		scanner := bufio.NewScanner(existing)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			var rec IntervalRecord
			if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
				continue
			}
			if h.since == "" {
				h.since = rec.Timestamp
			}
			h.cumBytes += rec.TotalBytes
			h.cumCrossAZ += rec.CrossAZBytes
			h.cumCost += rec.TotalCostUSD
			h.ring = append(h.ring, rec)
			if len(h.ring) > historyRingCap {
				h.ring = h.ring[1:]
			}
		}
		existing.Close()
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open history file %q: %w", path, err)
	}
	h.file = f

	if h.since == "" {
		h.since = time.Now().Format(time.RFC3339)
	}

	return h, nil
}

// Record appends one interval to the history file and updates the
// in-memory cumulative totals + bounded ring buffer.
func (h *HistoryStore) Record(snap Snapshot) {
	rec := IntervalRecord{
		Timestamp:    snap.Timestamp,
		TotalBytes:   snap.TotalBytes,
		CrossAZBytes: snap.CrossAZBytes,
		TotalCostUSD: snap.TotalCostUSD,
		ExecEvents:   snap.ExecEvents,
		UniqueFlows:  snap.FlowCount,
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if data, err := json.Marshal(rec); err == nil && h.file != nil {
		h.file.Write(append(data, '\n'))
	}

	h.cumBytes += rec.TotalBytes
	h.cumCrossAZ += rec.CrossAZBytes
	h.cumCost += rec.TotalCostUSD

	h.ring = append(h.ring, rec)
	if len(h.ring) > historyRingCap {
		h.ring = h.ring[1:]
	}
}

func (h *HistoryStore) HistoryJSON() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()

	summary := HistorySummary{
		Since:             h.since,
		CumulativeBytes:   h.cumBytes,
		CumulativeCrossAZ: h.cumCrossAZ,
		CumulativeCostUSD: h.cumCost,
		Intervals:         append([]IntervalRecord{}, h.ring...),
	}

	data, err := json.Marshal(summary)
	if err != nil {
		return []byte(`{"error":"failed to marshal history"}`)
	}
	return data
}
