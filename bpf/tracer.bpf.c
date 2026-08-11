// SPDX-License-Identifier: GPL-2.0

#include "headers/vmlinux.h"
#include "headers/bpf_helpers.h"
#include "headers/bpf_tracing.h"
#include "headers/bpf_core_read.h"
#include "headers/events.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_execve")
int handle_exec(void *ctx)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);

    return 0;
}


SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(handle_tcp_connect, struct sock *sk)
{
    bpf_printk("tcp_connect fired\n");

    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("ringbuf reserve FAILED\n");
        return 0;
    }

    bpf_printk("ringbuf reserve OK, about to submit\n");

    e->pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->src_ip =
        BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

    e->dst_ip =
        BPF_CORE_READ(sk, __sk_common.skc_daddr);

    e->src_port =
        BPF_CORE_READ(sk, __sk_common.skc_num);

    e->dst_port =
        BPF_CORE_READ(sk, __sk_common.skc_dport);

    bpf_printk("read values: src=%u dst=%u\n", e->src_ip, e->dst_ip);

    bpf_ringbuf_submit(e, 0);

    bpf_printk("submitted\n");

    return 0;
}