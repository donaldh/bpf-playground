// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 Red Hat */

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <string.h>

#include <bpf/libbpf.h>
#include "bpf-qdisc.skel.h"
#include <linux/pkt_sched.h>

#define BPF_TC_QDISC (1 << 3)

static struct env {
	bool verbose;
} env = { 0 };

const char *argp_program_version = "bpf-qdisc 0.0";
const char *argp_program_bug_address = "<donald.hunter@redhat.com>";
const char argp_program_doc[] =
"BPF qdisc.\n"
"\n"
"USAGE: ./bpf-qdisc [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
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

int main(int argc, char **argv)
{
	struct bpf_qdisc_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = bpf_qdisc_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = bpf_qdisc_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	struct bpf_link *link = bpf_map__attach_struct_ops(skel->maps.fifo);
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "Failed to attach BPF struct_ops: %s\n", strerror(-err));
		goto cleanup;
	}

	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = 1,
			    .attach_point = BPF_TC_QDISC,
			    .parent = TC_H_ROOT,
			    .handle = 0x8000000,
			    .qdisc = "bpf_fifo");

	err = bpf_tc_hook_create(&hook);
	if (err) {
		fprintf(stderr, "Failed to create tc hook: %s\n", strerror(-err));
		goto cleanup;
	}

	printf("Ctrl-C to exit ...\n");
        while (!exiting) {
		err = sleep(1);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			continue;
		}
	}

cleanup:
	/* Clean up */
	bpf_qdisc_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
