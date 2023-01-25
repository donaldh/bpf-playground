// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2023 Red Hat */

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <string.h>

#include "dns-trace.skel.h"
#include "dns-trace.h"

#include <linux/btf.h>
#include <bpf/btf.h>

static struct env {
	int interval;
	bool verbose;
} env = { 1, 0 };

const char *argp_program_version = "dns-trace 0.0";
const char *argp_program_bug_address = "<donald.hunter@redhat.com>";
const char argp_program_doc[] =
"BPF program to trace DNS requests.\n"
"\n"
"USAGE: ./dns-trace [-v]\n";

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

static int process_event(void *ctx, void *data, size_t len)
{
	if (sizeof(struct dns_event) > len) {
		fprintf(stderr, "Message too short, discarding\n");
		return 1;
	}
	struct dns_event *event = (struct dns_event *) data;

	fprintf(stderr, "Received dns event id=%x\n", event->id);
	return 0;
}

int main(int argc, char **argv)
{
	struct dns_trace_bpf *skel;
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
	skel = dns_trace_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = dns_trace_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = dns_trace_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	struct ring_buffer* ringbuf =
		ring_buffer__new(bpf_map__fd(skel->maps.dns_events), process_event, NULL, NULL);
        while (!exiting) {
		ring_buffer__poll(ringbuf, 100);
	}

cleanup:
	/* Clean up */
	dns_trace_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
