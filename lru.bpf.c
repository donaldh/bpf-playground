// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Red Hat */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include "lru.h"

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv4_lru_key);
	__type(value, struct value);
	__uint(map_flags, BPF_F_NO_COMMON_LRU);
	__uint(max_entries, 240);
} ipv4_lru_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, long);
	__uint(max_entries, 1);
} cpu_hits SEC(".maps");

void *lookup(__u32 ipaddr)
{
        struct ipv4_lru_key key = {
		.data = ipaddr
	};

	void *value = bpf_map_lookup_elem(&ipv4_lru_map, &key);
	if (!value) {
		struct value v = { };
		int r = bpf_map_update_elem(&ipv4_lru_map, &key, &v, BPF_ANY);
		if (r < 0) {
			char *update_err_msg = "lru: bpf_map_update_elem returned %d";
			bpf_trace_printk(update_err_msg, sizeof(update_err_msg), -r);
		}
		value = bpf_map_lookup_elem(&ipv4_lru_map, &key);
	}

	__u32 index = 0;
	long *count = bpf_map_lookup_elem(&cpu_hits, &index);
        if (count)
                __sync_fetch_and_add(count, 1);

	return value;
}

void count_by_prefix(struct iphdr *ip, __u32 len) {
	struct value *value = lookup(ip->daddr);
        if (value) {
		__sync_fetch_and_add(&value->packets, 1);
		__sync_fetch_and_add(&value->bytes, len);
        }
}

SEC("tc")
int tc_counter(struct __sk_buff *skb) {
	struct iphdr ip;

	if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip, sizeof(ip)) < 0)
		return 0;

	count_by_prefix(&ip, skb->len);

        return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
