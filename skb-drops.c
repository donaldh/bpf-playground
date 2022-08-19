// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Red Hat */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <string.h>

#include "skb-drops.skel.h"

const char * const drop_reasons[] = {
	"SKB_NOT_DROPPED_YET",
	"NOT_SPECIFIED",
	"NO_SOCKET",
	"PKT_TOO_SMALL",
	"TCP_CSUM",
	"SOCKET_FILTER",
	"UDP_CSUM",
	"NETFILTER_DROP",
	"OTHERHOST",
	"IP_CSUM",
	"IP_INHDR",
	"IP_RPFILTER",
	"UNICAST_IN_L2_MULTICAST",
	"XFRM_POLICY",
	"IP_NOPROTO",
	"SOCKET_RCVBUFF",
	"PROTO_MEM",
	"TCP_MD5NOTFOUND",
	"TCP_MD5UNEXPECTED",
	"TCP_MD5FAILURE",
	"SOCKET_BACKLOG",
	"TCP_FLAGS",
	"TCP_ZEROWINDOW",
	"TCP_OLD_DATA",
	"TCP_OVERWINDOW",
	"TCP_OFOMERGE",
	"TCP_RFC7323_PAWS",
	"TCP_INVALID_SEQUENCE",
	"TCP_RESET",
	"TCP_INVALID_SYN",
	"TCP_CLOSE",
	"TCP_FASTOPEN",
	"TCP_OLD_ACK",
	"TCP_TOO_OLD_ACK",
	"TCP_ACK_UNSENT_DATA",
	"TCP_OFO_QUEUE_PRUNE",
	"TCP_OFO_DROP",
	"IP_OUTNOROUTES",
	"BPF_CGROUP_EGRESS",
	"IPV6DISABLED",
	"NEIGH_CREATEFAIL",
	"NEIGH_FAILED",
	"NEIGH_QUEUEFULL",
	"NEIGH_DEAD",
	"TC_EGRESS",
	"QDISC_DROP",
	"CPU_BACKLOG",
	"XDP",
	"TC_INGRESS",
	"UNHANDLED_PROTO",
	"SKB_CSUM",
	"SKB_GSO_SEG",
	"SKB_UCOPY_FAULT",
	"DEV_HDR",
	"DEV_READY",
	"FULL_RING",
	"NOMEM",
	"HDR_TRUNC",
	"TAP_FILTER",
	"TAP_TXFILTER",
	"ICMP_CSUM",
       	"INVALID_PROTO",
	"IP_INADDRERRORS",
	"IP_INNOROUTES",
	"PKT_TOO_BIG",
	"MAX",
};

static struct env {
	char ifname[IF_NAMESIZE];
	int ifindex;
	int interval;
	bool verbose;
} env = {"", -1, 1, 0};

const char *argp_program_version = "tccounter 0.0";
const char *argp_program_bug_address = "<donald.hunter@redhat.com>";
const char argp_program_doc[] =
"BPF tccounter demo application.\n"
"\n"
"Trace packets at the tc hook and report packet statistics.\n"
"\n"
"USAGE: ./tccounter [-v]\n";

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
		printf("%24s : %llu drops\n", drop_reasons[next_key], value);
		cur_key = &next_key;
	} while (next == 0);
}


int main(int argc, char **argv)
{
	struct skb_drops_bpf *skel;
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

        //	int prog_fd = bpf_program__fd(skel->progs.count_drops);
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
