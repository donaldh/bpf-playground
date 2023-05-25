/*
 * Copyright (c) 2015 PLUMgrid, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * bpf_log2() and bpf_log2l() copied from
 * https://github.com/iovisor/bcc/blob/master/src/cc/export/helpers.h
 */
#ifndef __BPF_LOG2_H
#define __BPF_LOG2_H

static inline __attribute__((always_inline))
unsigned int bpf_log2(unsigned int v)
{
	unsigned int r;
	unsigned int shift;

	r = (v > 0xFFFF) << 4; v >>= r;
	shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
	shift = (v > 0xF) << 2; v >>= shift; r |= shift;
	shift = (v > 0x3) << 1; v >>= shift; r |= shift;
	r |= (v >> 1);
	return r;
}

static inline __attribute__((always_inline))
unsigned int bpf_log2l(unsigned long v)
{
	unsigned int hi = v >> 32;
	if (hi)
		return bpf_log2(hi) + 32 + 1;
	else
		return bpf_log2(v) + 1;
}

#endif
