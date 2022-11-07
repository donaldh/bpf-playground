/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022 Red Hat */
#ifndef __QUEUE_STACK_H
#define __QUEUE_STACK_H

struct ipv4_value {
	union {
		__u32 addr;
		__u8 octets[4];
	};
};

struct value {
	__u64 packets;
	__u64 bytes;
};

#endif /* __QUEUE_STACK_H */
