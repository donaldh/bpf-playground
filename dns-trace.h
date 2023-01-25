/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023 Red Hat */
#ifndef __DNS_TRACE_H
#define __DNS_TRACE_H

#include <linux/bpf.h>

#define IFNAMSIZ 16
#define MAXMSG 512

struct dns_event {
	__u64 duration;
	char ifname[IFNAMSIZ];
	__u32 srcip;
	__u32 dstip;
	__u16 length;
	unsigned char payload[MAXMSG];
	__u16 id;
	__u16 flags;
};

#endif /* __DNS_TRACE_H */
