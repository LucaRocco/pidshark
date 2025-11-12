#ifndef __MAPS_H__
#define __MAPS_H__

#include "common.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

typedef union scratch
{
	struct process proc;
} scratch_t;

struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, u32);
	__type(value, scratch_t);
} scratch_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, struct process);
} process_lru SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} EXECS SEC(".maps");

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

static __always_inline struct process* init_process(pid_t pid, u32 scratch_idx)
{
	scratch_t* scratch =
	    (scratch_t*)bpf_map_lookup_elem(&scratch_map, &scratch_idx);
	if (scratch == NULL)
	{
		bpf_printk("scratch == null");
		return NULL;
	}

	bpf_printk("sizeof scratch->proc = %d, sizeof struct process = %d, "
	           "sizeof scratch proc args = %d",
	           sizeof(scratch->proc), sizeof(struct process),
	           sizeof(scratch->proc.args));
	if (sizeof(scratch->proc) > sizeof(struct process))
	{
		bpf_printk("Builtin memset in maps if");
		__builtin_memset(&scratch->proc, 0, sizeof(struct process));
	}

	bpf_map_update_elem(&process_lru, &pid, &scratch->proc, BPF_ANY);

	return (struct process*)bpf_map_lookup_elem(&process_lru, &pid);
}

#endif
