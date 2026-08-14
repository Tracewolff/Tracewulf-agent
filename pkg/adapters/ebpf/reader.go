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

type ringbufEvent struct {
	Pid     uint32
	Comm    [16]byte
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
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

func resolveName(cache *k8s.Cache, ip string) (label string, nodeZone string) {
	if info, ok := cache.LookupPod(ip); ok {
		label = fmt.Sprintf("pod:%s/%s", info.Namespace, info.Name)
		if node, ok := cache.LookupNode(info.Node); ok {
			nodeZone = fmt.Sprintf(" (node=%s zone=%s)", node.Name, node.Zone)
		}
		return label, nodeZone
	}
	if info, ok := cache.LookupService(ip); ok {
		return fmt.Sprintf("svc:%s/%s", info.Namespace, info.Name), ""
	}
	return ip, ""
}

// ReadEvents consumes events from the ring buffer until it is closed
// (normal shutdown) or an unexpected error occurs.
func ReadEvents(rd *ringbuf.Reader, podCache *k8s.Cache) error {
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

		comm := string(bytes.TrimRight(e.Comm[:], "\x00"))

		if e.DstIP == 0 {
			fmt.Printf("[EXEC] PID=%d COMM=%s\n", e.Pid, comm)
			continue
		}

		srcIP := net.IPv4(byte(e.SrcIP), byte(e.SrcIP>>8), byte(e.SrcIP>>16), byte(e.SrcIP>>24)).String()
		dstIP := net.IPv4(byte(e.DstIP), byte(e.DstIP>>8), byte(e.DstIP>>16), byte(e.DstIP>>24)).String()

		srcName, srcNodeZone := resolveName(podCache, srcIP)
		dstName, _ := resolveName(podCache, dstIP)

		class := classify(dstIP)

		fmt.Printf(
			"[TCP][%s] proto=TCP PID=%d COMM=%s %s:%d%s -> %s:%d\n",
			class,
			e.Pid,
			comm,
			srcName,
			swapUint16(e.SrcPort),
			srcNodeZone,
			dstName,
			swapUint16(e.DstPort),
		)
	}
}
