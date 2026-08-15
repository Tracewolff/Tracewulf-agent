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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct sock *);
} sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct sock *);
} recv_sock_map SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_execve")
int handle_exec(void *ctx)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->src_ip = 0;
    e->dst_ip = 0;
    e->src_port = 0;
    e->dst_port = 0;
    e->bytes = 0;
    e->type = EVENT_EXEC;

    bpf_ringbuf_submit(e, 0);

    return 0;
}


SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(handle_tcp_connect_entry, struct sock *sk)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&sock_map, &pid, &sk, BPF_ANY);
    return 0;
}


SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(handle_tcp_connect_exit, int ret)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct sock **skp = bpf_map_lookup_elem(&sock_map, &pid);
    if (!skp)
        return 0;

    struct sock *sk = *skp;
    bpf_map_delete_elem(&sock_map, &pid);

    if (ret != 0)
        return 0;

    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dst_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    e->bytes = 0;
    e->type = EVENT_CONNECT;

    bpf_ringbuf_submit(e, 0);

    return 0;
}


SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(handle_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dst_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    e->bytes = size;
    e->type = EVENT_DATA;

    bpf_ringbuf_submit(e, 0);

    return 0;
}


SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(handle_tcp_recvmsg_entry, struct sock *sk)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&recv_sock_map, &pid, &sk, BPF_ANY);
    return 0;
}


SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(handle_tcp_recvmsg_exit, int ret)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct sock **skp = bpf_map_lookup_elem(&recv_sock_map, &pid);
    if (!skp)
        return 0;

    struct sock *sk = *skp;
    bpf_map_delete_elem(&recv_sock_map, &pid);

    if (ret <= 0)
        return 0;

    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dst_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    e->bytes = ret;
    e->type = EVENT_DATA;

    bpf_ringbuf_submit(e, 0);

    return 0;
}
