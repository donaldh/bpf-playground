/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __PACKETSTAT_H
#define __PACKETSTAT_H

struct key {
	union {
		__u32 srcip;
		__u8 octets[4];
	};
};

struct value {
	__u64 packets;
	__u64 bytes;
};

#endif /* __PACKETSTAT_H */
