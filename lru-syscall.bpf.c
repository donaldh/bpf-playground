// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Red Hat */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include "lru-syscall.h"

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(map_flags, BPF_F_NO_COMMON_LRU);
	__uint(max_entries, 100000);
} lru_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct value);
	__uint(max_entries, 1);
} cpu_hits SEC(".maps");

void *lookup(__u32 pid)
{
	int errors = 0;
	__u32 key = pid;
	void *value = bpf_map_lookup_elem(&lru_map, &key);
	if (!value) {
		__u32 new_value = 0;
		int r = bpf_map_update_elem(&lru_map, &key, &new_value, BPF_ANY);
		if (r < 0) {
			errors++;
			char *update_err_msg = "lru: bpf_map_update_elem returned %d";
			bpf_trace_printk(update_err_msg, sizeof(update_err_msg), -r);
		}
		value = bpf_map_lookup_elem(&lru_map, &key);
	}

	__u32 index = 0;
	struct value *cpu_val = bpf_map_lookup_elem(&cpu_hits, &index);
        if (cpu_val) {
                __sync_fetch_and_add(&cpu_val->calls, 1);
                __sync_fetch_and_add(&cpu_val->errors, errors);
	}

	return value;
}

void increment(__u32 pid) {
	__u32 *value = lookup(pid);
        if (value) {
		__sync_fetch_and_add(value, 1);
        }
}

SEC("raw_tracepoint/sys_enter")
int trace_sys_enter() {
	__u32 pid = bpf_get_current_pid_tgid() & 0xffffffff;

	increment(pid);

        return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
