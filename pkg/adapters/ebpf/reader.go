package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf/ringbuf"
)

type Event struct {
	Pid  uint32
	Comm [16]byte
}

func ReadEvents(rd *ringbuf.Reader) error {

	for {

		record, err := rd.Read()
		if err != nil {
			return err
		}

		var e Event

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}

		fmt.Printf(
			"PID=%d COMM=%s\n",
			e.Pid,
			bytes.TrimRight(e.Comm[:], "\x00"),
		)

	}

}