// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Red Hat  */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <netdb.h>

#include "lru-syscall.skel.h"
#include "lru-syscall.h"

static struct env {
	int interval;
	bool verbose;
} env = { 1, 0 };

const char *argp_program_version = "lru-syscall 0.0";
const char *argp_program_bug_address = "<donald.hunter@redhat.com>";
const char argp_program_doc[] =
"BPF lru-syscall demo application.\n"
"\n"
"USAGE: ./lru-syscall [-v]\n";

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

static void print_values(int map_fd, int cpu_fd)
{
	__u32 *cur_key = NULL;
        __u32 next_key;
	__u32 value;
	int err;

	printf("\033[H\033[JCPU Hits\n\n");

        int ncpus = libbpf_num_possible_cpus();
        __u32 index = 0;
        struct value values[ncpus];

        err = bpf_map_lookup_elem(cpu_fd, &index, &values);
        if (err < 0) {
		fprintf(stderr, "cpu map: bpf_map_lookup_elem returned %s\n",
			strerror(-err));
                return;
	}

        for (index = 0; index < ncpus; index++) {
		if (values[index].calls > 0) {
			printf("%8d: %12lld calls, %12lld errors\n",
			       index, values[index].calls, values[index].errors);
		}
	}

	printf("\n\nSyscall activity:\n\n");

	int i = 0;
	for (;;) {
		err = bpf_map_get_next_key(map_fd, cur_key, &next_key);
		if (err == -ENOENT)
			break;
		if (err < 0) {
			fprintf(stderr, "bpf_map_get_next_key %d returned %s\n", map_fd, strerror(-err));
			break;
		}

		long ret = bpf_map_lookup_elem(map_fd, &next_key, &value);
		if (ret < 0) {
			fprintf(stderr, "Failed to lookup elem with key %d: %s\n",
				next_key, strerror(-ret));
			break;
		}

		printf("%8d: %12d syscalls\n", next_key, value);

		cur_key = &next_key;
		i++;
		if (i == 50) {
			printf("...\n");
			break;
		}
	}
}

int main(int argc, char **argv)
{
	struct lru_syscall_bpf *skel;
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
	skel = lru_syscall_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = lru_syscall_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = lru_syscall_bpf__attach(skel);
	if (err < 0) {
		fprintf(stderr, "Error: lru_syscall_bpf__attach: %s\n",
			strerror(-err));
		goto cleanup;
	}

	int lru_fd = bpf_map__fd(skel->maps.lru_map);
	int cpu_fd = bpf_map__fd(skel->maps.cpu_hits);

        while (!exiting) {
		err = sleep(env.interval);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			continue;
		}

		print_values(lru_fd, cpu_fd);
	}

cleanup:
	/* Clean up */
	lru_syscall_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
