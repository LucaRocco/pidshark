#include "vmlinux.h"
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256);
} PROCESSES SEC(".maps");

SEC("raw_tracepoint/sched_process_exec")
int handle_sched_exec(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task;
    task = (struct task_struct *)ctx->args[0];

    struct process e = {};

    __u64 id = bpf_get_current_uid_gid();
    __u32 uid = id & 0xffffffff;
    __u32 gid = id >> 32;

    e.pid = BPF_CORE_READ(task, tgid);
    e.tid = BPF_CORE_READ(task, pid);
    e.user = uid;
    e.group = gid;
    bpf_get_current_comm(&e.command, sizeof(e.command));

    bpf_ringbuf_output(&PROCESSES, &e, sizeof(e), 0);

    return 0;
}

SEC("raw_tracepoint/sched_process_fork")
int handle_sched_fork(struct bpf_raw_tracepoint_args *ctx)
{
    return 0;
}

SEC("raw_tracepoint/sched_process_exit")
int handle_sched_exit(struct bpf_raw_tracepoint_args *ctx)
{
    return 0;
}

char LICENSE[] SEC("license") = "GPL";