#include "maps.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("raw_tracepoint/sched_process_exec")
int handle_sched_exec(struct bpf_raw_tracepoint_args* ctx)
{
    struct task_struct* task;
	struct linux_binprm* bprm;

	task = (struct task_struct*)ctx->args[0];
	bprm = (struct linux_binprm*)ctx->args[2];
	if (!task || !bprm)
		return 0;

	pid_t key = BPF_CORE_READ(task, tgid);
	struct process* e = bpf_map_lookup_elem(&process_lru, &key);
	if (e == NULL)
	{
		bpf_printk("Process e == null");
		e = init_process(key, 1);
		if (!e)
			return 0;
	}
	e->event_type = EVENT_EXEC;
	e->pid = BPF_CORE_READ(task, tgid);
	e->tid = BPF_CORE_READ(task, pid);
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);

	bpf_get_current_comm(&e->name, sizeof(e->name));
	BPF_CORE_READ_STR_INTO(e->filename, bprm, filename);

	e->ns_pid = get_task_ns_tgid(task);
	e->ns_tid = get_task_ns_pid(task);
	e->ns_ppid = get_task_ns_ppid(task);
	e->start_time = get_task_start_time(task);

	bpf_tail_call(ctx, &prog_array_tp, 0);

	return 0;
}

SEC("raw_tracepoint/sched_process_exec_tail_call")
int handle_sched_exec_tail(struct bpf_raw_tracepoint_args* ctx)
{
	struct task_struct* task = (struct task_struct*)ctx->args[0];
	if (!task)
		return 0;

	pid_t key = BPF_CORE_READ(task, tgid);
	struct process* e = bpf_map_lookup_elem(&process_lru, &key);
	if (!e)
		return 0;

	struct mm_struct* mm = get_mm_from_task(task);
	if (!mm)
		return 0;

	struct linux_binprm* bprm = (struct linux_binprm*)ctx->args[2];
	if (!bprm)
		return 0;

	unsigned long arg_start = get_arg_start_from_mm(mm);
	unsigned long env_start = get_env_start_from_mm(mm);

	bpf_probe_read_user_str(&e->args.argv, sizeof(e->args.argv),
	                        (void*)arg_start);
	bpf_probe_read_user_str(&e->args.envp, sizeof(e->args.envp),
	                        (void*)env_start);

	e->args.arg_start = arg_start;
	e->args.env_start = env_start;
	e->args.arg_end = get_arg_end_from_mm(mm);
	e->args.env_end = get_env_end_from_mm(mm);

	// event submit
	struct process* evt = bpf_ringbuf_reserve(&EXECS, sizeof(*e), 0);
	if (!evt)
		return 0;
	if (sizeof(*evt) < sizeof(struct process))
	{
		bpf_printk("Memcopy");
		__builtin_memcpy(evt, e, sizeof(*e));
	}
	bpf_ringbuf_submit(evt, 0);

	return 0;
}

SEC("raw_tracepoint/sched_process_fork")
int handle_sched_fork(struct bpf_raw_tracepoint_args* ctx)
{
	// struct task_struct* parent = (struct task_struct*)ctx->args[0];
	// struct task_struct* child = (struct task_struct*)ctx->args[1];

	// pid_t parent_tgid = BPF_CORE_READ(parent, tgid);
	// pid_t child_tgid = BPF_CORE_READ(child, tgid);

	// // This is the case of a new thread spawned by using clone() or clone3()
	// // Maybe we should take care of this??
	// if (parent_tgid == child_tgid)
	// {
	// 	return 0;
	// }

	// struct process p = {};

	// u64 uid_gid = bpf_get_current_uid_gid();

	// // Metadata
	// p.event_type = EVENT_FORK;

	// // User info
	// p.uid = uid_gid;
	// p.gid = uid_gid >> 32;

	// // Host related identifiers
	// p.pid = parent_tgid;
	// p.tid = BPF_CORE_READ(child, pid);
	// p.ppid = BPF_CORE_READ(parent, pid);

	// // Namespaced info
	// p.ns_pid = get_task_ns_tgid(child);
	// p.ns_tid = get_task_ns_pid(child);
	// p.ns_ppid = get_task_ns_ppid(child);

	// // Timestamps
	// p.start_time = get_task_start_time(child);
	// p.parent_start_time = get_task_start_time(parent);

	// // Command info
	// bpf_get_current_comm(&p.name, sizeof(p.name));

	// // Insert the current process to the internal process map. This will make
	// // the process available for the next child creation
	// int res =
	//     bpf_map_update_elem(&processes_map, &child_tgid, &p, BPF_NOEXIST);
	// if (res < 0)
	// {
	// 	return 0;
	// }

	// // Namespaces
	// p.namespaces.uts = BPF_CORE_READ(child, nsproxy, uts_ns, ns.inum);
	// p.namespaces.ipc = BPF_CORE_READ(child, nsproxy, ipc_ns, ns.inum);
	// p.namespaces.mnt = BPF_CORE_READ(child, nsproxy, mnt_ns, ns.inum);
	// p.namespaces.pid =
	//     BPF_CORE_READ(child, nsproxy, pid_ns_for_children, ns.inum);
	// p.namespaces.net = BPF_CORE_READ(child, nsproxy, net_ns, ns.inum);
	// p.namespaces.time = BPF_CORE_READ(child, nsproxy, time_ns, ns.inum);
	// p.namespaces.cgroup = BPF_CORE_READ(child, nsproxy, cgroup_ns, ns.inum);
	// bpf_get_current_comm(&p.name, sizeof(p.name));

	// bpf_ringbuf_output(&FORKS, &p, sizeof(p), 0);

	return 0;
}

SEC("raw_tracepoint/sched_process_exit")
int handle_sched_exit(struct bpf_raw_tracepoint_args* ctx)
{
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
