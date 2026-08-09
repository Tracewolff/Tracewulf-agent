#ifndef __EVENTS_H
#define __EVENTS_H

struct event {
    __u32 pid;
    char comm[16];

    __u32 src_ip;
    __u32 dst_ip;

    __u16 src_port;
    __u16 dst_port;
};

#endif