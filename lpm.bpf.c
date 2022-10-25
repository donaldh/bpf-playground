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
	__uint(max_entries, 255);
	__type(key, struct lpm_ipv4_key);
	__type(value, struct value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_ipv4 SEC(".maps");


SEC("tc")
int count_by_prefix(struct __sk_buff *skb) {
	struct iphdr ip;

	if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip, sizeof(ip)) < 0)
		return 0;

        struct lpm_ipv4_key key = {
		.trie_key.prefixlen = 32,
		.data = ip.daddr
	};

	struct value *value = bpf_map_lookup_elem(&lpm_ipv4, &key);
        if (value) {
		__sync_fetch_and_add(&value->packets, 1);
		__sync_fetch_and_add(&value->bytes, skb->len);
        }

        return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
