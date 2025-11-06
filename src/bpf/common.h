#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/*
type Process struct {
	EntityId          uint32         `json:"entityId"`
	ParentEntityId    uint32         `json:"parentEntityId"`
	Name              string         `json:"name"`
	Tid               int            `json:"tid"`
	Pid               int            `json:"pid"`
	Ppid              int            `json:"ppid"`
	NsTid             int            `json:"nsTid"`
	NsPid             int            `json:"nsPid"`
	NsPPid            int            `json:"nsPpid"`
	Uid               int            `json:"uid"`
	Gid               int            `json:"gid"`
	StartTime         time.Time      `json:"startTime"`
	ExitTime          time.Time      `json:"exitTime"`
	ExitStatus        int            `json:"exitStatus"`
	ThreadsIds        map[int]uint32 `json:"threadsIds"`
	ChildProcessesIds map[int]uint32 `json:"childProcessesIds"`
	ExecutionBinary   ProcessFile    `json:"executionBinary"`
	CmdlineArgs       []string       `json:"cmdlineArgs"`
	Envs              []string       `json:"envs"`
}*/

enum EVENT_TYPE {
	EXEC = 1,
	FORK = 2
};

struct process
{
	enum EVENT_TYPE event_type;
	pid_t pid;
	pid_t ppid;
	pid_t tid;
	pid_t ns_tid;
	pid_t ns_pid;
	pid_t ns_ppid;
	__u32 uid;
	__u32 gid;
	__u64 start_time;
	char name[16];
	char command[16];
};

static __always_inline u64 get_task_start_time(struct task_struct* task)
{
	if (bpf_core_enum_value_exists(enum bpf_func_id,
	                               BPF_FUNC_ktime_get_boot_ns))
	{
		if (bpf_core_field_exists(struct task_struct, start_boottime))
			return BPF_CORE_READ(task, start_boottime);
	}

	return BPF_CORE_READ(task, start_time);
}

static __always_inline pid_t get_task_pid_nr(struct task_struct* task)
{
	struct pid* pid = BPF_CORE_READ(task, thread_pid);
	unsigned int level = BPF_CORE_READ(pid, level);

	return BPF_CORE_READ(pid, numbers[level].nr);
}

static __always_inline pid_t get_task_ns_pid(struct task_struct* task)
{
	return get_task_pid_nr(task);
}

static __always_inline pid_t get_task_ns_tgid(struct task_struct* task)
{
	struct task_struct* leader = BPF_CORE_READ(task, group_leader);
	return get_task_pid_nr(task);
}

static __always_inline pid_t get_task_ns_ppid(struct task_struct* task)
{
	struct task_struct* real_parent = BPF_CORE_READ(task, real_parent);
	return get_task_pid_nr(task);
}