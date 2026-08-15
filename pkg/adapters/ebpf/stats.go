package ebpf

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

// costPerGB is the cross-AZ egress price used for estimation. Override with
// the TRACEWULF_COST_PER_GB env var (USD per GB). Defaults to a common
// AWS cross-AZ rate.
var costPerGB = func() float64 {
	if v := os.Getenv("TRACEWULF_COST_PER_GB"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return 0.01
}()

type connStat struct {
	Count    uint64
	Bytes    uint64
	LastSeen time.Time
	Class    string
	SrcZone  string
	DstZone  string
}

// crossAZ reports whether both zones are known and different. Unknown zones
// (Service destinations, external IPs) never count as cross-AZ — accuracy
// over completeness.
func (c *connStat) crossAZ() bool {
	return c.SrcZone != "" && c.DstZone != "" && c.SrcZone != c.DstZone
}

func (c *connStat) costUSD() float64 {
	if !c.crossAZ() {
		return 0
	}
	gb := float64(c.Bytes) / 1e9
	return gb * costPerGB
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

func (s *Stats) getOrCreate(key, class, srcZone, dstZone string) *connStat {
	c, ok := s.conns[key]
	if !ok {
		c = &connStat{Class: class, SrcZone: srcZone, DstZone: dstZone}
		s.conns[key] = c
	}
	// Zones shouldn't change mid-flow for the same key, but keep them
	// current in case a Pod's Node info updates between events.
	if srcZone != "" {
		c.SrcZone = srcZone
	}
	if dstZone != "" {
		c.DstZone = dstZone
	}
	return c
}

func (s *Stats) RecordTCP(srcName, dstName string, dstPort uint16, class, srcZone, dstZone string) {
	key := flowKey(srcName, dstName, dstPort)
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.getOrCreate(key, class, srcZone, dstZone)
	c.Count++
	c.LastSeen = time.Now()
}

func (s *Stats) RecordBytes(srcName, dstName string, dstPort uint16, class, srcZone, dstZone string, n uint64) {
	key := flowKey(srcName, dstName, dstPort)
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.getOrCreate(key, class, srcZone, dstZone)
	c.Bytes += n
	c.LastSeen = time.Now()
}

type FlowSummary struct {
	Flow     string  `json:"flow"`
	Class    string  `json:"class"`
	Count    uint64  `json:"count"`
	Bytes    uint64  `json:"bytes"`
	LastSeen string  `json:"last_seen"`
	SrcZone  string  `json:"src_zone,omitempty"`
	DstZone  string  `json:"dst_zone,omitempty"`
	CrossAZ  bool    `json:"cross_az"`
	CostUSD  float64 `json:"cost_usd"`
}

type Snapshot struct {
	Timestamp    string        `json:"timestamp"`
	ExecEvents   uint64        `json:"exec_events"`
	FlowCount    int           `json:"unique_flows"`
	TotalCostUSD float64       `json:"total_cost_usd"`
	CostPerGB    float64       `json:"cost_per_gb_usd"`
	Flows        []FlowSummary `json:"flows"`
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

	var totalCost float64
	flows := make([]FlowSummary, 0, len(keys))
	for _, k := range keys {
		c := s.conns[k]
		cost := c.costUSD()
		totalCost += cost
		flows = append(flows, FlowSummary{
			Flow:     k,
			Class:    c.Class,
			Count:    c.Count,
			Bytes:    c.Bytes,
			LastSeen: c.LastSeen.Format(time.RFC3339),
			SrcZone:  c.SrcZone,
			DstZone:  c.DstZone,
			CrossAZ:  c.crossAZ(),
			CostUSD:  cost,
		})
	}

	snap := Snapshot{
		Timestamp:    time.Now().Format(time.RFC3339),
		ExecEvents:   s.execCnt,
		FlowCount:    len(flows),
		TotalCostUSD: totalCost,
		CostPerGB:    costPerGB,
		Flows:        flows,
	}

	s.execCnt = 0
	s.conns = make(map[string]*connStat)

	return snap
}

func (s *Stats) LatestJSON() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastJSON == nil {
		return []byte(`{"timestamp":"","exec_events":0,"unique_flows":0,"total_cost_usd":0,"cost_per_gb_usd":0,"flows":[]}`)
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
