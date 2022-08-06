// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>

#include "tccounter.h"

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 32);
	__type(key, struct key);
	__type(value, struct value);
} packet_stats SEC(".maps");


static inline void count_by_srcip(__u32 srcip, int bytes)
{
	struct key key = {
		.srcip = srcip
	};
	struct value *value = bpf_map_lookup_elem(&packet_stats, &key);
	if (value) {
		__sync_fetch_and_add(&value->packets, 1);
		__sync_fetch_and_add(&value->bytes, bytes);
	} else {
		struct value newval = { 1, bytes };
		bpf_map_update_elem(&packet_stats, &key, &newval, BPF_NOEXIST);
	}
}

SEC("tc")
int count_packets(struct __sk_buff *skb)
{
        const int l3_off = ETH_HLEN;
        const int l4_off = l3_off + sizeof(struct iphdr);
        const int tcp_end = l4_off + sizeof(struct tcphdr);

        void *data = (void*)(long)skb->data;
        void *data_end = (void*)(long)skb->data_end;
        if (data_end < data + l4_off)
                return BPF_OK;

        struct ethhdr *eth = data;
        if (eth->h_proto != htons(ETH_P_IP))
                return BPF_OK;

        struct iphdr *ip = (struct iphdr *)(data + l3_off);
        if (ip->protocol != IPPROTO_TCP)
                return BPF_OK;

        struct tcphdr *tcph = (struct tcphdr *)(ip + 1);

        if (data_end < data + tcp_end)
                return BPF_OK;

        __u32 saddr = ip->saddr;
	count_by_srcip(saddr, skb->data_end - skb->data);

	return BPF_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
