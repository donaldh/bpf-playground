// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Red Hat */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <string.h>

#include "skb-drops.skel.h"

#include <linux/btf.h>
#include <bpf/btf.h>

static const char ** drop_reasons;

static struct env {
	int interval;
	bool verbose;
} env = { 1, 0 };

const char *argp_program_version = "skb-drops 0.0";
const char *argp_program_bug_address = "<donald.hunter@redhat.com>";
const char argp_program_doc[] =
"BPF program to count SKB drop reasons.\n"
"\n"
"Trace SKB drops and display a summary count of drop reasons.\n"
"\n"
"USAGE: ./skb-drops [-v]\n";

static const struct argp_option opts[] = {
	{ "interval", 'i', "seconds", 0, "Interval between reports" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'i':
		env.interval = atoi(arg);
		break;
	case 'v':
		env.verbose = true;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static void print_values(int map_fd)
{
	int *cur_key = NULL;
	int next_key;
	int next;
	do {
		next = bpf_map_get_next_key(map_fd, cur_key, &next_key);
		if (next == -ENOENT)
			break;
		if (next < 0) {
			fprintf(stderr, "bpf_map_get_next_key %d returned %s\n", map_fd, strerror(-next));
			break;
		}
		__u64 value;
		int ret = bpf_map_lookup_elem(map_fd, &next_key, &value);
		if (ret < 0) {
			fprintf(stderr, "Failed to lookup elem with key %d: %s\n", *cur_key, strerror(-ret));
			break;
		}
		printf("%24s : %8llu drops\n", drop_reasons[next_key], value);
		cur_key = &next_key;
	} while (next == 0);
}


static bool init_drop_reasons() {
	const char * const prefix = "SKB_DROP_REASON_";
	const int prefixlen = strlen(prefix);

	struct btf* kernel_btf = btf__load_vmlinux_btf();
	if (!kernel_btf) {
		fprintf(stderr, "Failed to load kernel btf\n");
		return false;
	}
	__s32 drop_reason_id = btf__find_by_name(kernel_btf, "skb_drop_reason");
	if (drop_reason_id < 0) {
		perror("Failed to look up id for skb_drop_reason");
		return false;
	}
	const struct btf_type* drop_reason = btf__type_by_id(kernel_btf, drop_reason_id);
	if (!drop_reason) {
		perror("Failed to get type information for skb_drop_reason");
		return false;
	}
	const struct btf_enum* e = btf_enum(drop_reason);
	const int num_reasons = btf_vlen(drop_reason);

	drop_reasons = calloc(num_reasons, sizeof(char *));
	if (!drop_reasons) {
		perror("Failed to allocate memory for skb_drop_reason");
		return false;
	}

	for (int i = 0; i < num_reasons; e++, i++) {
		const char *type_name = btf__str_by_offset(kernel_btf, e->name_off);
		if (strncmp(type_name, prefix, prefixlen) == 0)
			type_name += prefixlen;
		drop_reasons[e->val] = type_name;
		if (env.verbose)
			fprintf(stderr, "%24s = %d\n", type_name, e->val);
	}

	return true;
}


int main(int argc, char **argv)
{
	struct skb_drops_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!init_drop_reasons()) {
		return 1;
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = skb_drops_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = skb_drops_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = skb_drops_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	int stats_fd = bpf_map__fd(skel->maps.drop_reasons);

        while (!exiting) {
		err = sleep(env.interval);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			continue;
		}

                printf("\033[H\033[JSKB Drop Reasons\n\n");

		print_values(stats_fd);
	}

cleanup:
	/* Clean up */
	skb_drops_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
