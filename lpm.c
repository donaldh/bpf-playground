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

#include "lpm.skel.h"
#include "lpm.h"

static struct env {
	char ifname[IF_NAMESIZE];
	int ifindex;
	int interval;
	bool verbose;
} env = { "", -1, 1, 0 };

const char *argp_program_version = "lpm 0.0";
const char *argp_program_bug_address = "<donald.hunter@redhat.com>";
const char argp_program_doc[] =
"BPF lpm demo application.\n"
"\n"
"USAGE: ./lpm [-v]\n";

static const struct argp_option opts[] = {
	{ "device", 'd', "ifname", 0, "Attach to device" },
	{ "interval", 'i', "seconds", 0, "Interval between reports" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'd':
		if (strlen(arg) >= IF_NAMESIZE) {
			fprintf(stderr, "ERR: --device name too long\n");
			return ARGP_ERR_UNKNOWN;
		}
		strncpy(env.ifname, arg, IF_NAMESIZE);
		env.ifindex = if_nametoindex(env.ifname);
		if (env.ifindex == 0) {
			fprintf(stderr,
				"ERR: --device name unknown err(%d):%s\n",
				errno, strerror(errno));
			return ARGP_ERR_UNKNOWN;
		}
		break;
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
	struct ipv4_lpm_key *cur_key = NULL;
        struct ipv4_lpm_key next_key;
	struct value value;
	int err;

	for (;;) {
		err = bpf_map_get_next_key(map_fd, cur_key, &next_key);
		if (err == -ENOENT)
			break;
		if (err < 0) {
			fprintf(stderr, "bpf_map_get_next_key %d returned %s\n", map_fd, strerror(-err));
			break;
		}

		int ret = bpf_map_lookup_elem(map_fd, &next_key, &value);
		if (ret < 0) {
			fprintf(stderr, "Failed to lookup elem with key %d: %s\n", next_key.data, strerror(-ret));
			break;
		}

		/* Use key and value here */

		struct in_addr src_addr = {
			.s_addr = next_key.data
		};
		char *prefix_ip = inet_ntoa(src_addr);

		printf("%16s/%-2d: %12lld packets, %12lld bytes\n", prefix_ip, next_key.prefixlen, value.packets, value.bytes);

		cur_key = &next_key;
	}
}

static int add_prefix_entry(int lpm_fd, __u32 addr, __u32 prefixlen, struct value *value)
{
	struct ipv4_lpm_key ipv4_key = {
		.prefixlen = prefixlen,
		.data = addr
	};
	return bpf_map_update_elem(lpm_fd, &ipv4_key, value, BPF_NOEXIST);
}

int main(int argc, char **argv)
{
	struct lpm_bpf *skel;
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
	skel = lpm_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = lpm_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Add some sample prefixes */
	int lpm_fd = bpf_map__fd(skel->maps.ipv4_lpm_map);

        struct value value = {};
	__u32 data;
	inet_pton(AF_INET, "0.0.0.0", &data);
	err = add_prefix_entry(lpm_fd, data, 0, &value);
        if (err) {
		fprintf(stderr, "Failed to add prefix to lpm\n");
		goto cleanup;
        }

	inet_pton(AF_INET, "10.0.0.0", &data);
	err = add_prefix_entry(lpm_fd, data, 8, &value);
        if (err) {
		fprintf(stderr, "Failed to add prefix to lpm\n");
		goto cleanup;
        }

	inet_pton(AF_INET, "192.168.0.0", &data);
	err = add_prefix_entry(lpm_fd, data, 16, &value);
        if (err) {
		fprintf(stderr, "Failed to add prefix to lpm\n");
		goto cleanup;
        }

	inet_pton(AF_INET, "10.11.2.0", &data);
	err = add_prefix_entry(lpm_fd, data, 24, &value);
        if (err) {
		fprintf(stderr, "Failed to add prefix to lpm\n");
		goto cleanup;
        }

	inet_pton(AF_INET, "10.11.2.2", &data);
	err = add_prefix_entry(lpm_fd, data, 32, &value);
        if (err) {
		fprintf(stderr, "Failed to add prefix to lpm\n");
		goto cleanup;
        }

        int prog_fd = bpf_program__fd(skel->progs.tc_counter);
	LIBBPF_OPTS(bpf_tc_hook, hook,
		    .ifindex = env.ifindex,
		    .attach_point = BPF_TC_INGRESS);
	LIBBPF_OPTS(bpf_tc_opts, opts,
		    .handle = 1,
		    .priority = 1,
		    .flags = BPF_TC_F_REPLACE,
		    .prog_fd = prog_fd);

	err = bpf_tc_hook_create(&hook);
	err = err == -EEXIST ? 0 : err;
	if (err < 0) {
		fprintf(stderr, "Error: bpf_tc_hook_create: %s\n",
			strerror(-err));
		goto cleanup;
	}
	err = bpf_tc_attach(&hook, &opts);
	if (err < 0) {
		fprintf(stderr, "Error: bpf_tc_attach: %s\n",
			strerror(-err));
		goto cleanup;
	}

        while (!exiting) {
		err = sleep(env.interval);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			continue;
		}

		printf("\033[H\033[JPacket stats by prefix\n\n");

		print_values(lpm_fd);
	}

cleanup:
	/* Clean up */
	lpm_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
