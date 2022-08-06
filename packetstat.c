// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
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
#include "packetstat.h"
#include <bpf/bpf.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "packetstat.skel.h"
#include "packetstat.h"

static struct env {
	char ifname[IF_NAMESIZE];
	int ifindex;
	int interval;
	bool verbose;
} env = { "", -1, 1, 0 };

const char *argp_program_version = "packetstat 0.0";
const char *argp_program_bug_address = "<donald.hunter@redhat.com>";
const char argp_program_doc[] =
"BPF packetstat demo application.\n"
"\n"
"It traces xdp packets and reports packet statistics.\n"
"\n"
"USAGE: ./packetstat [-v]\n";

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
	struct key *cur_key = NULL;
	struct key next_key;
	int next;
	do {
		next = bpf_map_get_next_key(map_fd, cur_key, &next_key);
		if (next == -ENOENT)
			break;
		if (next < 0) {
			fprintf(stderr, "bpf_map_get_next_key %d returned %s\n", map_fd, strerror(-next));
			break;
		}

		struct in_addr src_addr = {
			.s_addr = next_key.srcip
		};
		char *src_ip = inet_ntoa(src_addr);

		struct value value;
		int ret = bpf_map_lookup_elem(map_fd, &next_key, &value);
		if (ret < 0) {
			fprintf(stderr, "Failed to lookup elem with key %s: %s\n", src_ip, strerror(-ret));
			break;
		}
		printf("%s: %lld packets, %lld bytes\n", src_ip, value.packets, value.bytes);
		cur_key = &next_key;
	} while (next == 0);
}


int main(int argc, char **argv)
{
	struct packetstat_bpf *skel;
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
	skel = packetstat_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = packetstat_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = packetstat_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	int prog_fd = bpf_program__fd(skel->progs.count_packets);
	int stats_fd = bpf_map__fd(skel->maps.packet_stats);

	bpf_xdp_attach(env.ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL);

	while (!exiting) {
		err = sleep(env.interval);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			continue;
		}

		print_values(stats_fd);
	}

cleanup:
	/* Clean up */
	packetstat_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
