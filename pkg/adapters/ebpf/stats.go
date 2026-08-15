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
	mu       sync.Mutex
	conns    map[string]*connStat
	execCnt  uint64
	lastJSON []byte
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

type FlowSummary struct {
	Flow     string `json:"flow"`
	Class    string `json:"class"`
	Count    uint64 `json:"count"`
	LastSeen string `json:"last_seen"`
}

type Snapshot struct {
	Timestamp  string        `json:"timestamp"`
	ExecEvents uint64        `json:"exec_events"`
	FlowCount  int           `json:"unique_flows"`
	Flows      []FlowSummary `json:"flows"`
}

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

// LatestJSON returns the most recently computed snapshot as JSON bytes.
// Safe to call concurrently from an HTTP handler.
func (s *Stats) LatestJSON() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastJSON == nil {
		return []byte(`{"timestamp":"","exec_events":0,"unique_flows":0,"flows":[]}`)
	}
	return s.lastJSON
}

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
					continue
				}
				s.mu.Lock()
				s.lastJSON = data
				s.mu.Unlock()
			}
		}
	}()
}
