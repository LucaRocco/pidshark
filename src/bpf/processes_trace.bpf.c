#include "common.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 15360); // 1024 * 15 just because I like it
	__type(key, u32);
	__type(value, struct process);
} processes_map SEC(".maps");

struct prog_array_tp
{
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} prog_array_tp SEC(".maps");

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
	bpf_get_current_comm(&e.name, sizeof(e.name));
	
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
	// Maybe we should take care of this??
	if (parent_tgid == child_tgid)
	{
		return 0;
	}

	struct process p = {};

	u64 uid_gid = bpf_get_current_uid_gid();

	// Metadata
	p.event_type = EVENT_FORK;

	// User info
	p.uid = uid_gid;
	p.gid = uid_gid >> 32;

	// Host related identifiers
	p.pid = parent_tgid;
	p.tid = BPF_CORE_READ(child, pid);
	p.ppid = BPF_CORE_READ(parent, pid);

	// Namespaced info
	p.ns_pid = get_task_ns_tgid(child);
	p.ns_tid = get_task_ns_pid(child);
	p.ns_ppid = get_task_ns_ppid(child);

	// Timestamps
	p.start_time = get_task_start_time(child);
	p.parent_start_time = get_task_start_time(parent);

	// Command info
	bpf_get_current_comm(&p.name, sizeof(p.name));

	// Insert the current process to the internal process map. This will make
	// the process available for the next child creation
	int res =
	    bpf_map_update_elem(&processes_map, &child_tgid, &p, BPF_NOEXIST);
	if (res < 0)
	{
		return 0;
	}

	// Namespaces
	p.namespaces.uts = BPF_CORE_READ(child, nsproxy, uts_ns, ns.inum);
	p.namespaces.ipc = BPF_CORE_READ(child, nsproxy, ipc_ns, ns.inum);
	p.namespaces.mnt = BPF_CORE_READ(child, nsproxy, mnt_ns, ns.inum);
	p.namespaces.pid =BPF_CORE_READ(child, nsproxy, pid_ns_for_children, ns.inum);
	p.namespaces.net = BPF_CORE_READ(child, nsproxy, net_ns, ns.inum);
	p.namespaces.time = BPF_CORE_READ(child, nsproxy, time_ns, ns.inum);
	p.namespaces.cgroup = BPF_CORE_READ(child, nsproxy, cgroup_ns, ns.inum);

	bpf_ringbuf_output(&FORKS, &p, sizeof(p), 0);

	return 0;
}

SEC("raw_tracepoint/sched_process_exit")
int handle_sched_exit(struct bpf_raw_tracepoint_args* ctx)
{
	return 0;
}

char LICENSE[] SEC("license") = "GPL";