// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Red Hat */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include "protostat.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 255);
	__type(key, __u32);
	__type(value, struct value);
} packet_stats SEC(".maps");

static inline void count_by_proto(__u8 protocol, int bytes)
{
	__u32 index = protocol;
	struct value *value = bpf_map_lookup_elem(&packet_stats, &index);
	if (value) {
		__sync_fetch_and_add(&value->packets, 1);
		__sync_fetch_and_add(&value->bytes, bytes);
	}
}

SEC("xdp")
int count_xdp_packets(struct xdp_md *ctx)
{
        void *pos = (void*) (long) ctx->data;
	void *end = (void*) (long) ctx->data_end;

        struct ethhdr *eth = pos;
	int hdrsize = sizeof(*eth);
	if (pos + hdrsize > end)
		return XDP_PASS;

	pos += hdrsize;

	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return XDP_PASS;

	struct iphdr *ip = pos;
	hdrsize = sizeof(*ip);
	if (pos + hdrsize > end)
		return XDP_PASS;

	count_by_proto(ip->protocol, ctx->data_end - ctx->data);

	return XDP_PASS;
}

SEC("tc")
int count_tc_packets(struct __sk_buff *skb) {
	struct iphdr ip;

	if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip, sizeof(ip)) < 0)
		return 0;

        count_by_proto(ip.protocol, skb->len);
        return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
