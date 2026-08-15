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
	Bytes    uint64
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

func flowKey(srcName, dstName string, dstPort uint16) string {
	return fmt.Sprintf("%s -> %s:%d", srcName, dstName, dstPort)
}

func (s *Stats) getOrCreate(key, class string) *connStat {
	c, ok := s.conns[key]
	if !ok {
		c = &connStat{Class: class}
		s.conns[key] = c
	}
	return c
}

func (s *Stats) RecordTCP(srcName, dstName string, dstPort uint16, class string) {
	key := flowKey(srcName, dstName, dstPort)
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.getOrCreate(key, class)
	c.Count++
	c.LastSeen = time.Now()
}

func (s *Stats) RecordBytes(srcName, dstName string, dstPort uint16, class string, n uint64) {
	key := flowKey(srcName, dstName, dstPort)
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.getOrCreate(key, class)
	c.Bytes += n
	c.LastSeen = time.Now()
}

type FlowSummary struct {
	Flow     string `json:"flow"`
	Class    string `json:"class"`
	Count    uint64 `json:"count"`
	Bytes    uint64 `json:"bytes"`
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
		return s.conns[keys[i]].Bytes > s.conns[keys[j]].Bytes
	})

	flows := make([]FlowSummary, 0, len(keys))
	for _, k := range keys {
		c := s.conns[k]
		flows = append(flows, FlowSummary{
			Flow:     k,
			Class:    c.Class,
			Count:    c.Count,
			Bytes:    c.Bytes,
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
