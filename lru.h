/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 Red Hat */
#ifndef __LRU_H
#define __LRU_H

struct ipv4_lru_key {
        union {
		__u32 data;
		__u8 octets[4];
        };
};

struct value {
	__u64 packets;
	__u64 bytes;
};

#endif /* __LRU_H */
