// -*- indent-tabs-mode: nil -*-
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Red Hat */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include "queue-stack.h"

struct {
        __uint(type, BPF_MAP_TYPE_QUEUE);
        __type(value, struct ipv4_value);
        __uint(max_entries, 10);
} queue SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_STACK);
        __type(value, struct ipv4_value);
        __uint(max_entries, 10);
} stack SEC(".maps");

int take_one(__u32 *elem)
{
        return bpf_map_pop_elem(&queue, elem);
}

SEC("tc")
int tc_counter(struct __sk_buff *skb)
{
        struct iphdr ip;

        if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip, sizeof(ip)) < 0)
                return 0;

        return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
