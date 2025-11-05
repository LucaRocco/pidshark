#include "vmlinux.h"

struct process
{
    pid_t pid;
    pid_t tid;
    __u32 user;
    __u32 group;
    char command[16]
};