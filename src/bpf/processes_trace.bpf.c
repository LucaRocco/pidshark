#include "common.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256);
} PROCESSES SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256);
} FORKS SEC(".maps");

SEC("raw_tracepoint/sched_process_exec")
int handle_sched_exec(struct bpf_raw_tracepoint_args* ctx)
{
	struct task_struct* task;
	task = (struct task_struct*)ctx->args[0];

	struct process e = {};

	__u64 id = bpf_get_current_uid_gid();
	__u32 uid = id & 0xffffffff;
	__u32 gid = id >> 32;

	e.pid = BPF_CORE_READ(task, tgid);
	e.tid = BPF_CORE_READ(task, pid);
	bpf_get_current_comm(&e.command, sizeof(e.command));

	bpf_ringbuf_output(&PROCESSES, &e, sizeof(e), 0);

	return 0;
}

SEC("raw_tracepoint/sched_process_fork")
int handle_sched_fork(struct bpf_raw_tracepoint_args* ctx)
{
	struct task_struct* parent = (struct task_struct*)ctx->args[0];
	struct task_struct* child = (struct task_struct*)ctx->args[1];

	pid_t parent_tgid = BPF_CORE_READ(parent, tgid);
	pid_t child_tgid = BPF_CORE_READ(child, tgid);

	// This is the case of a new thread spawned by using clone() or clone3()
	if (parent_tgid == child_tgid)
	{
		return 0;
	}

	struct process p = {};

	u64 uid_gid = bpf_get_current_uid_gid();

	p.event_type = FORK;
	p.uid = uid_gid;
	p.gid = uid_gid >> 32;
	p.tid = BPF_CORE_READ(child, pid);
	p.pid = parent_tgid;
	p.ns_pid = get_task_ns_tgid(child);
	p.ns_tid = get_task_ns_pid(child);
	p.ns_ppid = get_task_ns_ppid(child);
	p.start_time = get_task_start_time(child);
	bpf_get_current_comm(&p.command, sizeof(p.command));

	bpf_ringbuf_output(&FORKS, &p, sizeof(p), 0);

	return 0;
}

SEC("raw_tracepoint/sched_process_exit")
int handle_sched_exit(struct bpf_raw_tracepoint_args* ctx)
{
	return 0;
}

char LICENSE[] SEC("license") = "GPL";