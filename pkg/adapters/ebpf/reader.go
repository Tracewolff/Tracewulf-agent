package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/Tracewolff/Tracewulf-agent/pkg/adapters/k8s"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	eventExec    = 0
	eventConnect = 1
	eventData    = 2
)

type ringbufEvent struct {
	Pid     uint32
	Comm    [16]byte
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Bytes   uint64
	Type    uint8
	_       [7]byte // struct padding to match C layout, do not remove
}

func swapUint16(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}

var privateBlocks = []*net.IPNet{
	mustParseCIDR("10.0.0.0/8"),
	mustParseCIDR("172.16.0.0/12"),
	mustParseCIDR("192.168.0.0/16"),
	mustParseCIDR("127.0.0.0/8"),
}

func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(fmt.Sprintf("invalid CIDR %q: %v", s, err))
	}
	return n
}

func classify(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "unknown"
	}
	for _, block := range privateBlocks {
		if block.Contains(parsed) {
			return "internal"
		}
	}
	return "external"
}

func resolveName(cache *k8s.Cache, ip string) string {
	if info, ok := cache.LookupPod(ip); ok {
		return fmt.Sprintf("pod:%s/%s", info.Namespace, info.Name)
	}
	if info, ok := cache.LookupService(ip); ok {
		return fmt.Sprintf("svc:%s/%s", info.Namespace, info.Name)
	}
	return ip
}

// resolveZone returns the AZ of the given IP, but ONLY when it's a Pod IP
// whose Node's zone label is known. Service IPs and external IPs return ""
// (unknown) rather than a guess, because a Service can route to a backend
// Pod in any zone — attributing a zone here would be inaccurate.
func resolveZone(cache *k8s.Cache, ip string) string {
	info, ok := cache.LookupPod(ip)
	if !ok || info.Node == "" {
		return ""
	}
	node, ok := cache.LookupNode(info.Node)
	if !ok {
		return ""
	}
	if node.Zone == "unknown" {
		return ""
	}
	return node.Zone
}

func ReadEvents(rd *ringbuf.Reader, podCache *k8s.Cache, stats *Stats) error {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read ringbuf: %w", err)
		}

		var e ringbufEvent
		if err := binary.Read(
			bytes.NewReader(record.RawSample),
			binary.LittleEndian,
			&e,
		); err != nil {
			continue
		}

		if e.Type == eventExec {
			stats.RecordExec()
			continue
		}

		srcIP := net.IPv4(byte(e.SrcIP), byte(e.SrcIP>>8), byte(e.SrcIP>>16), byte(e.SrcIP>>24)).String()
		dstIP := net.IPv4(byte(e.DstIP), byte(e.DstIP>>8), byte(e.DstIP>>16), byte(e.DstIP>>24)).String()

		srcName := resolveName(podCache, srcIP)
		dstName := resolveName(podCache, dstIP)
		srcZone := resolveZone(podCache, srcIP)
		dstZone := resolveZone(podCache, dstIP)
		class := classify(dstIP)
		dstPort := swapUint16(e.DstPort)

		switch e.Type {
		case eventConnect:
			stats.RecordTCP(srcName, dstName, dstPort, class, srcZone, dstZone)
		case eventData:
			stats.RecordBytes(srcName, dstName, dstPort, class, srcZone, dstZone, e.Bytes)
		}
	}
}
