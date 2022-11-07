// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Red Hat */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include "bloom.h"

struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 4);
} cpu_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
	__type(value, __u32);
	__uint(max_entries, 1000);
	__uint(map_extra, 3);
} bloom_filter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct ipv4_key);
	__type(value, struct value);
	__uint(max_entries, 1000);
} hash_table SEC(".maps");

void *lookup(__u32 key)
{
	if (bpf_map_peek_elem(&bloom_filter, &key) == 0) {
		/* Verify not a false positive and fetch an associated
		 * value using a secondary lookup, e.g. in a hash table
		 */
		return bpf_map_lookup_elem(&hash_table, &key);
	}
	return 0;
}

void count_by_prefix(struct iphdr *ip, __u32 len)
{
	struct value *value = lookup(ip->daddr);
        if (value) {
		__sync_fetch_and_add(&value->packets, 1);
		__sync_fetch_and_add(&value->bytes, len);
        }
}

SEC("tc")
int tc_counter(struct __sk_buff *skb)
{
	struct iphdr ip;

	if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip, sizeof(ip)) < 0)
		return 0;

	count_by_prefix(&ip, skb->len);

	__u32 key = 0;
	__u32 *value = bpf_map_lookup_elem(&cpu_map, &key);
	if (!value)
		return 2;

        return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
