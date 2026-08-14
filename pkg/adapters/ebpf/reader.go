package ebpf

import (
	"bytes"
	"encoding/binary"
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

func resolveName(cache *k8s.Cache, ip string) string {
	if info, ok := cache.Lookup(ip); ok {
		return fmt.Sprintf("%s/%s", info.Namespace, info.Name)
	}
	return ip
}

func ReadEvents(rd *ringbuf.Reader, podCache *k8s.Cache) error {
	for {
		record, err := rd.Read()
		if err != nil {
			return err
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
			fmt.Printf(
				"[EXEC] PID=%d COMM=%s\n",
				e.Pid,
				comm,
			)
			continue
		}

		srcIP := net.IPv4(
			byte(e.SrcIP),
			byte(e.SrcIP>>8),
			byte(e.SrcIP>>16),
			byte(e.SrcIP>>24),
		).String()

		dstIP := net.IPv4(
			byte(e.DstIP),
			byte(e.DstIP>>8),
			byte(e.DstIP>>16),
			byte(e.DstIP>>24),
		).String()

		srcName := resolveName(podCache, srcIP)
		dstName := resolveName(podCache, dstIP)

		fmt.Printf(
			"[TCP] PID=%d COMM=%s %s:%d -> %s:%d\n",
			e.Pid,
			comm,
			srcName,
			swapUint16(e.SrcPort),
			dstName,
			swapUint16(e.DstPort),
		)
	}
}
