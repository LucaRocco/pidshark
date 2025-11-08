#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

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
	ParentStartTime
	ExitTime          time.Time      `json:"exitTime"`
	ExitStatus        int            `json:"exitStatus"`
	ThreadsIds        map[int]uint32 `json:"threadsIds"` // useless
	ChildProcessesIds map[int]uint32 `json:"childProcessesIds"` // useless
	ExecutionBinary   ProcessFile    `json:"executionBinary"`
	CmdlineArgs       []string       `json:"cmdlineArgs"`
	Envs              []string       `json:"envs"`
}*/

typedef u8 event_type;

const event_type EVENT_EXEC = 1;
const event_type EVENT_FORK = 2;

struct namespaces
{
	__u32 uts;
	__u32 ipc;
	__u32 mnt;
	__u32 pid;
	__u32 net;
	__u32 time;
	__u32 cgroup;
};

struct process
{
	event_type event_type;
	uint8_t name[16];
	pid_t tid;
	pid_t pid;
	pid_t ppid;
	pid_t ns_tid;
	pid_t ns_pid;
	pid_t ns_ppid;
	__u32 uid;
	__u32 gid;
	__u64 start_time;
	__u64 parent_start_time;
	char filename[16];
	char argv[16];
	char envp[16];
	struct namespaces namespaces;
};

struct process_exit
{
	pid_t pid;
	pid_t ppid;
	pid_t ns_pid;
	pid_t ns_ppid;
	__u64 start_time;
	__u64 parent_start_time;
	__u32 exit_time;
	__u32 exit_status;
	__u32 signal;
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

static __always_inline struct mm_struct *get_mm_from_task(struct task_struct *task)
{
    return BPF_CORE_READ(task, mm);
}

static __always_inline unsigned long get_arg_start_from_mm(struct mm_struct *mm)
{
    return BPF_CORE_READ(mm, arg_start);
}

static __always_inline unsigned long get_arg_end_from_mm(struct mm_struct *mm)
{
    return BPF_CORE_READ(mm, arg_end);
}

static __always_inline unsigned long get_env_start_from_mm(struct mm_struct *mm)
{
    return BPF_CORE_READ(mm, env_start);
}

static __always_inline unsigned long get_env_end_from_mm(struct mm_struct *mm)
{
    return BPF_CORE_READ(mm, env_end);
}

static __always_inline int get_argc_from_bprm(struct linux_binprm *bprm)
{
    return BPF_CORE_READ(bprm, argc);
}
