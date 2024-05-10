/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 Red Hat */
#ifndef __LRU_H
#define __LRU_H

struct value {
	__u64 calls;
	__u64 errors;
};

#endif /* __LRU_H */
