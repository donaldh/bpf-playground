// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Red Hat */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32);
	__type(key, int);
	__type(value, __u64);
} drop_reasons SEC(".maps");

struct kfree_skb_args {
	void *skbaddr;
	void *location;
	unsigned short protocol;
	enum skb_drop_reason reason;
};

SEC("tracepoint/skb/kfree_skb")
int count_drops(struct kfree_skb_args *ctx) {
	int key = ctx->reason;
	__u64 *value = bpf_map_lookup_elem(&drop_reasons, &key);
	if (value) {
		__sync_fetch_and_add(value, 1);
	} else {
		__u64 newval = 1;
		bpf_map_update_elem(&drop_reasons, &key, &newval, BPF_NOEXIST);
	}

	return BPF_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
