/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022 Red Hat */
#ifndef __PACKETSTAT_H
#define __PACKETSTAT_H

struct ipv4_lpm_key {
	__u32 prefixlen;
        union {
		__u32 data;
		__u8 octets[4];
        };
};

struct value {
	__u64 packets;
	__u64 bytes;
};

#endif /* __PACKETSTAT_H */