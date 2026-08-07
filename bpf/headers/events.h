#ifndef __EVENTS_H
#define __EVENTS_H

struct event {
    __u32 pid;
    char comm[16];
};

#endif