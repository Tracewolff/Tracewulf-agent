package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

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

func ReadEvents(rd *ringbuf.Reader) error {
	for {
		record, err := rd.Read()
		if err != nil {
			return err
		}

		fmt.Printf("[DEBUG] got record, len=%d bytes\n", len(record.RawSample))

		var e ringbufEvent

		if err := binary.Read(
			bytes.NewReader(record.RawSample),
			binary.LittleEndian,
			&e,
		); err != nil {
			fmt.Printf("[DEBUG] binary.Read FAILED: %v\n", err)
			continue
		}

		comm := string(bytes.TrimRight(e.Comm[:], "\x00"))

		fmt.Printf(
			"[RAW] PID=%d COMM=%s SrcIP=%d DstIP=%d SrcPort=%d DstPort=%d\n",
			e.Pid, comm, e.SrcIP, e.DstIP, e.SrcPort, e.DstPort,
		)

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
		)

		dstIP := net.IPv4(
			byte(e.DstIP),
			byte(e.DstIP>>8),
			byte(e.DstIP>>16),
			byte(e.DstIP>>24),
		)

		fmt.Printf(
			"[TCP] PID=%d COMM=%s %s:%d -> %s:%d\n",
			e.Pid,
			comm,
			srcIP,
			e.SrcPort,
			dstIP,
			e.DstPort,
		)
	}
}
