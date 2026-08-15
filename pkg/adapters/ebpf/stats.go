package ebpf

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

type connStat struct {
	Count    uint64
	LastSeen time.Time
	Class    string
}

type Stats struct {
	mu      sync.Mutex
	conns   map[string]*connStat
	execCnt uint64
}

func NewStats() *Stats {
	return &Stats{conns: make(map[string]*connStat)}
}

func (s *Stats) RecordExec() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.execCnt++
}

func (s *Stats) RecordTCP(srcName, dstName string, dstPort uint16, class string) {
	key := fmt.Sprintf("%s -> %s:%d", srcName, dstName, dstPort)
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.conns[key]
	if !ok {
		c = &connStat{Class: class}
		s.conns[key] = c
	}
	c.Count++
	c.LastSeen = time.Now()
}

// FlowSummary is the JSON-serializable representation of one aggregated flow.
type FlowSummary struct {
	Flow     string `json:"flow"`
	Class    string `json:"class"`
	Count    uint64 `json:"count"`
	LastSeen string `json:"last_seen"`
}

// Snapshot is the JSON-serializable representation of one reporting interval.
type Snapshot struct {
	Timestamp  string        `json:"timestamp"`
	ExecEvents uint64        `json:"exec_events"`
	FlowCount  int           `json:"unique_flows"`
	Flows      []FlowSummary `json:"flows"`
}

// snapshotAndReset builds a Snapshot from current counters, sorted by count
// descending, then clears counters for the next interval.
func (s *Stats) snapshotAndReset() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	keys := make([]string, 0, len(s.conns))
	for k := range s.conns {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return s.conns[keys[i]].Count > s.conns[keys[j]].Count
	})

	flows := make([]FlowSummary, 0, len(keys))
	for _, k := range keys {
		c := s.conns[k]
		flows = append(flows, FlowSummary{
			Flow:     k,
			Class:    c.Class,
			Count:    c.Count,
			LastSeen: c.LastSeen.Format(time.RFC3339),
		})
	}

	snap := Snapshot{
		Timestamp:  time.Now().Format(time.RFC3339),
		ExecEvents: s.execCnt,
		FlowCount:  len(flows),
		Flows:      flows,
	}

	s.execCnt = 0
	s.conns = make(map[string]*connStat)

	return snap
}

// StartReporter emits a JSON snapshot every interval and resets counters,
// keeping memory bounded (sliding window, not lifetime accumulation).
func (s *Stats) StartReporter(interval time.Duration, stopCh <-chan struct{}) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				snap := s.snapshotAndReset()
				data, err := json.Marshal(snap)
				if err != nil {
					fmt.Println(`{"error":"failed to marshal snapshot"}`)
					continue
				}
				fmt.Println(string(data))
			}
		}
	}()
}
