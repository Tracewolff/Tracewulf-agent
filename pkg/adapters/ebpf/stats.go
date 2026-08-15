package ebpf

import (
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

// RecordTCP aggregates by src identity -> dst identity:port, ignoring the
// ephemeral source port so repeated connections to the same destination
// collapse into one counter instead of growing unbounded.
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

// StartReporter prints an aggregated summary every interval and then
// resets counters, so memory stays bounded (a sliding window, not a
// lifetime accumulation).
func (s *Stats) StartReporter(interval time.Duration, stopCh <-chan struct{}) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				s.printAndReset()
			}
		}
	}()
}

func (s *Stats) printAndReset() {
	s.mu.Lock()
	execCnt := s.execCnt
	keys := make([]string, 0, len(s.conns))
	for k := range s.conns {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return s.conns[keys[i]].Count > s.conns[keys[j]].Count
	})

	fmt.Printf("\n=== TraceWulf summary (last interval) === exec_events=%d unique_flows=%d\n", execCnt, len(keys))
	limit := 15
	for i, k := range keys {
		if i >= limit {
			fmt.Printf("... and %d more flows\n", len(keys)-limit)
			break
		}
		c := s.conns[k]
		fmt.Printf("[%s] %s count=%d last=%s\n", c.Class, k, c.Count, c.LastSeen.Format("15:04:05"))
	}

	s.execCnt = 0
	s.conns = make(map[string]*connStat)
	s.mu.Unlock()
}
