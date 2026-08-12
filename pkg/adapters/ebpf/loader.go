package ebpf

import (
    "log"

    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/cilium/ebpf/rlimit"
)

func Start() error {
    if err := rlimit.RemoveMemlock(); err != nil {
        return err
    }

    objs := tracerObjects{}

    if err := loadTracerObjects(&objs, nil); err != nil {
        return err
    }
    defer objs.Close()

    tp, err := link.Tracepoint(
        "syscalls",
        "sys_enter_execve",
        objs.HandleExec,
        nil,
    )
    if err != nil {
        return err
    }
    defer tp.Close()

    kpEntry, err := link.Kprobe(
        "tcp_v4_connect",
        objs.HandleTcpConnectEntry,
        nil,
    )
    if err != nil {
        return err
    }
    defer kpEntry.Close()

    kpExit, err := link.Kretprobe(
        "tcp_v4_connect",
        objs.HandleTcpConnectExit,
        nil,
    )
    if err != nil {
        return err
    }
    defer kpExit.Close()

    rd, err := ringbuf.NewReader(objs.Events)
    if err != nil {
        return err
    }
    defer rd.Close()

    log.Println("TraceWulf eBPF program attached")
    log.Println("Watching execve() and tcp_v4_connect() events...")

    return ReadEvents(rd)
}
