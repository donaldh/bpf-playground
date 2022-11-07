// -*- indent-tabs-mode: nil -*-
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Red Hat */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct inner_map {
        __uint(type, BPF_MAP_TYPE_DEVMAP);
        __uint(max_entries, 10);
        __type(key, __u32);
        __type(value, __u32);
} inner_map1 SEC(".maps"), inner_map2 SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
        __uint(max_entries, 2);
        __type(key, __u32);
        __array(values, struct inner_map);
} outer_map SEC(".maps") = {
        .values = { &inner_map1,
                    &inner_map2 }
};


long redirect_by_tos(__u32 tos, __u32 fd)
{
        struct bpf_map *inner_map;
        __u32 *value;

        inner_map = bpf_map_lookup_elem(&outer_map, &tos);
        if (!inner_map)
                return XDP_PASS;

        return bpf_redirect_map(inner_map, fd, XDP_PASS);
}

SEC("xdp")
int redirect(struct xdp_md *ctx)
{
        void *pos = (void*) (long) ctx->data;
	void *end = (void*) (long) ctx->data_end;

        struct ethhdr *eth = pos;
	int hdrsize = sizeof(*eth);
	if (pos + hdrsize > end)
		return XDP_DROP;

	pos += hdrsize;

	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return XDP_PASS;

	struct iphdr *ip = pos;
	hdrsize = sizeof(*ip);
	if (pos + hdrsize > end)
		return XDP_DROP;

        return redirect_by_tos(0, ip->tos);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
