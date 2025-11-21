#ifndef __MAPS_H__
#define __MAPS_H__

#include "common.h"
#include "vmlinux.h"
#include <bits/floatn.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define BLOCK_SIZE 512
#define TOTAL_SIZE 1024
#define NUM_BLOCKS (TOTAL_SIZE / BLOCK_SIZE)

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

static __always_inline void init_large_struct(struct process *p) {

    return;
}

static __always_inline struct process* init_process(pid_t pid, u32 scratch_idx)
{
    scratch_t* scratch = (scratch_t *)bpf_map_lookup_elem(&scratch_map, &scratch_idx);
    if (!scratch) {
        return NULL;
    }

    struct process *p = &scratch->proc;

    const int off_after_namespaces = offsetof(struct process, args);

    __builtin_memset(p, 0, off_after_namespaces);

    const int off_args_start = offsetof(struct process, args.start);
    __builtin_memset((void *)p + off_args_start,
                     0,
                     sizeof(u32) * 2);   /* start + end */

    const int off_envs_start = offsetof(struct process, envs.start);
    __builtin_memset((void *)p + off_envs_start,
                     0,
                     sizeof(u32) * 2);   /* start + end */


    bpf_map_update_elem(&process_lru, &pid, p, BPF_ANY);

    return bpf_map_lookup_elem(&process_lru, &pid);
}

#endif