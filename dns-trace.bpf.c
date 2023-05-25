// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 Red Hat */

#include <linux/bpf.h>
#include <stdbool.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "dns-trace.h"
#include "bpf-log2.h"

struct dns_header
{
	__u16 id;
	__u16 flags;
	__u16 qdcount;
	__u16 ancount;
	__u16 nscount;
	__u16 arcount;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} dns_events SEC(".maps");

struct request_key {
	__u16 id;
};

struct request_val {
	__u64 ts;
	__u32 srcip;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, struct request_key);
	__type(value, struct request_val);
} requests SEC(".maps");

struct latency_key {
        __u32 ip;
        __u64 slot;
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 256);
        __type(key, struct latency_key);
        __type(value, __u64);
} latency SEC(".maps");

struct qname_key {
	__u32 ip;
        unsigned char qname[MAXNAME];
};

struct {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __uint(max_entries, 256);
        __type(key, struct qname_key);
        __type(value, __u64);
} query_count SEC(".maps");

struct rcode_key {
  __u32 ip;
  __u16 rcode;
};

struct {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __uint(max_entries, 256);
        __type(key, struct rcode_key);
        __type(value, __u64);
} rcode_count SEC(".maps");


struct sk_buff {
        unsigned char *data;
	unsigned int len;
} __attribute__((preserve_access_index));

struct trace_event_raw_net_dev_template {
	struct sk_buff *skbaddr;
} __attribute__((preserve_access_index));

static inline int do_trace(unsigned char *data, unsigned int len)
{
	__u64 initval = 1;
	unsigned char *end = data + len;

	struct ethhdr eth;
	if (data + sizeof(eth) > end)
		return 0;
	bpf_probe_read_kernel(&eth, sizeof(eth), data);
	data += sizeof(eth);

	if (eth.h_proto != bpf_htons(ETH_P_IP))
		return 0;

	struct iphdr ip;
	if (data + sizeof(ip) > end)
		return 0;
	bpf_probe_read_kernel(&ip, sizeof(ip), data);
	data += sizeof(ip);

	if (ip.protocol != IPPROTO_UDP)
		return 0;

	struct udphdr udp;
	if (data + sizeof(udp) > end)
		return 0;
	bpf_probe_read_kernel(&udp, sizeof(udp), data);
	data += sizeof(udp);

	if (udp.source == bpf_htons(53) || udp.dest == bpf_htons(53)) {
		struct dns_header dns;
		if (data + sizeof(dns) > end)
			return 0;
		bpf_probe_read_kernel(&dns, sizeof(dns), data);

		unsigned int length = bpf_ntohs(udp.len) - sizeof(udp);
		if (length > MAXMSG) {
			length = MAXMSG;
		}

		if (data + length > end) {
			char format[] = "dns-trace: length too long: wanted %d, got %d\n";
			bpf_trace_printk(format, sizeof(format), length, end - data);
			return 0;
		}

		struct request_key req_key = {
			.id = dns.id
		};

		struct request_val newval = {};

#ifdef DEBUG
		char format[] = "dns-trace: found DNS packet: id=0x%x, flags=0x%04x\n";
		bpf_trace_printk(format, sizeof(format), bpf_ntohs(dns.id), bpf_ntohs(dns.flags));
#endif
		if ((dns.flags & 0x80) == 0) { /* query */
			if (bpf_map_lookup_elem(&requests, &req_key) == NULL) { // only interested in first query packet with id
				newval.ts = bpf_ktime_get_ns();
				newval.srcip = ip.saddr;
				bpf_map_update_elem(&requests, &req_key, &newval, BPF_ANY);
			}
		} else { /* response */
			struct request_val *value = bpf_map_lookup_elem(&requests, &req_key);
			if (value != 0 && value->srcip == ip.daddr) { /* first response packet with right dst IP */
				struct dns_event *evt = bpf_ringbuf_reserve(&dns_events, sizeof(struct dns_event), 0);
				if (!evt) return 1;

				evt->id = bpf_ntohs(dns.id);
				evt->flags = bpf_ntohs(dns.flags);
				evt->duration = bpf_ktime_get_ns() - value->ts;
				evt->srcip = bpf_ntohl(ip.daddr);
				evt->dstip = bpf_ntohl(ip.saddr);
				evt->length = length;
				bpf_probe_read_kernel(&evt->payload, length, data);

				/* build a log2 latency histogram keyed by resolver IP and slot */
                                struct latency_key lkey = {};
				lkey.ip = evt->srcip;
				lkey.slot = bpf_log2l(evt->duration / 1000000);

				__u64 *lvalue = bpf_map_lookup_elem(&latency, &lkey);
                                if (lvalue) {
					__sync_fetch_and_add(lvalue, 1);
                                } else {
					bpf_map_update_elem(&latency, &lkey,
							    &initval, BPF_ANY);
                                }

				/* build a histogram of qname lookups keyed by resolver IP */
                                struct qname_key qkey = {};
				qkey.ip = evt->srcip;
				unsigned char *pos = evt->payload + sizeof(struct dns_header);
				__u16 i = 0;
				for (i = 0; i < MAXNAME; i++) {
					if (pos[i] == 0) break;
					qkey.qname[i] = pos[i];
				}

				__u64 *qvalue = bpf_map_lookup_elem(&query_count, &qkey);
                                if (qvalue) {
					__sync_fetch_and_add(qvalue, 1);
                                } else {
                                        bpf_map_update_elem(&query_count, &qkey,
                                                            &initval, BPF_ANY);
                                }

				/* build a histogram of response codes, keyed by resolver IP */
                                struct rcode_key rkey = {};
				rkey.ip = evt->srcip;
				rkey.rcode = (dns.flags & 0x0f00) >> 8;

				__u64 *rvalue = bpf_map_lookup_elem(&rcode_count, &rkey);
                                if (rvalue) {
					__sync_fetch_and_add(rvalue, 1);
                                } else {
                                        bpf_map_update_elem(&rcode_count, &rkey,
                                                            &initval, BPF_ANY);
                                }

                                bpf_ringbuf_submit(evt, 0);
                                bpf_map_delete_elem(&requests, &req_key);
#ifdef DEBUG
				char format[] = "dns-trace: dns_event added to ringbuf\n";
				bpf_trace_printk(format, sizeof(format));
#endif
			}
		}
	}

	return 0;
}


SEC("tracepoint/net/net_dev_queue")
int trace_net_packets(struct trace_event_raw_net_dev_template *ctx) {
	unsigned char *data = BPF_CORE_READ(ctx, skbaddr, data);
	unsigned int len = BPF_CORE_READ(ctx, skbaddr, len);

	do_trace(data, len);

	return BPF_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
