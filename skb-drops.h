/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __SKB_DROPS_H
#define __SKB_DROPS_H

#include "vmlinux.h"

struct drop_key {
  enum skb_drop_reason reason;
};

#endif /* __SKB_DROPS_H */
