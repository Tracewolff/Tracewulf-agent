package ebpf

import (
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

func Start() error {

	var objs tracerObjects

	if err := loadTracerObjects(&objs, nil); err != nil {
		return err
	}

	kp, err := link.Kprobe(
		"__x64_sys_execve",
		objs.HandleExec,
		nil,
	)
	if err != nil {
		return err
	}
	defer kp.Close()

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return err
	}
	defer reader.Close()

	return ReadEvents(reader)
}