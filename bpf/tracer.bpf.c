// SPDX-License-Identifier: GPL-2.0

#include "headers/vmlinux.h"
#include "headers/bpf_helpers.h"
#include "headers/bpf_tracing.h"
#include "headers/events.h"

char LICENSE[] SEC("license") = "GPL";

/*
 * Ring Buffer
 *
 * The kernel writes events here.
 * Our Go daemon will continuously read from this buffer.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);   // 16 MB
} events SEC(".maps");


/*
 * Trace every execve() syscall.
 *
 * Every time a process starts
 * (bash, ls, cat, kubectl, docker, go, etc.)
 * this function executes inside the Linux kernel.
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_exec(void *ctx)
{
    struct event *e;

    /*
     * Reserve memory inside the Ring Buffer.
     */
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

    if (!e)
        return 0;

    /*
     * Current Process ID
     */
    e->pid = bpf_get_current_pid_tgid() >> 32;

    /*
     * Process Name
     *
     * Example:
     * bash
     * ls
     * vim
     * kubectl
     */
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /*
     * Send event to userspace.
     */
    bpf_ringbuf_submit(e, 0);

    return 0;
}