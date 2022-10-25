// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Red Hat */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include "lpm.h"

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct ipv4_lpm_key);
	__type(value, struct value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 255);
} ipv4_lpm_map SEC(".maps");


void *lookup(__u32 ipaddr)
{
        struct ipv4_lpm_key key = {
		.prefixlen = 32,
		.data = ipaddr
	};

	return bpf_map_lookup_elem(&ipv4_lpm_map, &key);
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
