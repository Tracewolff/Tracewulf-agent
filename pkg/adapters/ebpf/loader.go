package ebpf

import (
	"log"
	"time"

	"github.com/Tracewolff/Tracewulf-agent/pkg/adapters/exporter"
	"github.com/Tracewolff/Tracewulf-agent/pkg/adapters/k8s"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func Start(podCache *k8s.Cache, stopCh <-chan struct{}) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	objs := tracerObjects{}
	if err := loadTracerObjects(&objs, nil); err != nil {
		return err
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExec, nil)
	if err != nil {
		return err
	}
	defer tp.Close()

	kpEntry, err := link.Kprobe("tcp_v4_connect", objs.HandleTcpConnectEntry, nil)
	if err != nil {
		return err
	}
	defer kpEntry.Close()

	kpExit, err := link.Kretprobe("tcp_v4_connect", objs.HandleTcpConnectExit, nil)
	if err != nil {
		return err
	}
	defer kpExit.Close()

	kpSend, err := link.Kprobe("tcp_sendmsg", objs.HandleTcpSendmsg, nil)
	if err != nil {
		return err
	}
	defer kpSend.Close()

	kpRecvEntry, err := link.Kprobe("tcp_recvmsg", objs.HandleTcpRecvmsgEntry, nil)
	if err != nil {
		return err
	}
	defer kpRecvEntry.Close()

	kpRecvExit, err := link.Kretprobe("tcp_recvmsg", objs.HandleTcpRecvmsgExit, nil)
	if err != nil {
		return err
	}
	defer kpRecvExit.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return err
	}
	defer rd.Close()

	log.Println("TraceWulf eBPF program attached")
	log.Println("Watching execve(), tcp_v4_connect(), tcp_sendmsg(), tcp_recvmsg() events...")

	history, err := NewHistoryStore()
	if err != nil {
		return err
	}
	log.Printf("History persisting to disk, cumulative cost so far: session restored")

	stats := NewStats()
	stats.StartReporter(10*time.Second, stopCh, history)

	exporter.Start("0.0.0.0:9090", stats, history)

	go func() {
		<-stopCh
		rd.Close()
	}()

	return ReadEvents(rd, podCache, stats)
}
