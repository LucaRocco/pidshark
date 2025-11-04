// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} PROCESSES SEC(".maps");

struct exec_event {
    int pid;
};

SEC("raw_tracepoint/sched/sched_process_exec")
int handle_sched_exec(struct bpf_raw_tracepoint_args *ctx)
{
    struct exec_event event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32; // get current PID

    // Submit the event to user space
    bpf_perf_event_output(ctx, &PROCESSES, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";