#ifndef __EVENTS_H
#define __EVENTS_H

enum event_type {
    EVENT_EXEC    = 0,
    EVENT_CONNECT = 1,
    EVENT_SEND    = 2,  // egress — this is what counts toward cost
    EVENT_RECV    = 3,  // ingress — tracked for visibility, not billed
};

struct event {
    __u32 pid;
    char comm[16];

    __u32 src_ip;
    __u32 dst_ip;

    __u16 src_port;
    __u16 dst_port;

    __u64 bytes;
    __u8  type;
};

#endif
