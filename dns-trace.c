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

#include <resolv.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netinet/in.h>

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

const char *rcode_names[] = {
	"NOERROR",
	"FORMERR",
	"SERVFAIL",
	"NXDOMAIN",
	"NOTIMP",
	"REFUSED",
	"YXDOMAIN",
	"YXRRSET",
	"NXRRSET",
	"NOTAUTH",
	"NOTZONE",
	"ns_r_max"
};

const char * rcode_name(ns_rcode code)
{
	static char buffer[10];
	if (code > ns_r_max) {
		snprintf(buffer, 10, "%d", code);
		return buffer;
	} else {
		return rcode_names[code];
	}
}

const char *type_names[] = {
	"invalid",
	"A",
	"NS",
	"MD",
	"MF",
	"CNAME",
	"SOA",
	"MB",
	"MG",
	"MR",
	"NULL",
	"WKS",
	"PTR",
	"HINFO",
	"MINFO",
	"MX",
	"TXT",
	"RP",
	"AFSDB",
	"X25",
	"ISDN",
	"RT",
	"NSAP",
	"NSAP_PTR",
	"SIG",
	"KEY",
	"PX",
	"GPOS",
	"AAAA",
	"LOC",
	"NIMLOC",
	"SRV"
};

static const char *type_name(ns_type type)
{
	static char buffer[10];
	if (type > ns_t_srv) {
		snprintf(buffer, 10, "%d", type);
		return buffer;
	} else {
		return type_names[type];
	}
}

static int print_records(bool q, ns_msg *msg, const char *name, ns_sect section)
{
	int i;
	for (i = 0; i < ns_msg_count(*msg, section); i++) {
		char data[100] = { 0 };
		ns_rr rr;
		int err = ns_parserr(msg, section, i, &rr);
		if (err) {
			perror("ns_parserr");
			return 1;
		}

		if (q) {
			printf("%s: %5s %s\n",
			       name,  type_name(ns_rr_type(rr)), ns_rr_name(rr));
		} else {
			const char *rdata = (const char *) ns_rr_rdata(rr);
			int rdlen = ns_rr_rdlen(rr);
			switch (ns_rr_type(rr)) {
			case ns_t_a:
				if (rdlen == NS_INADDRSZ)
					inet_ntop(AF_INET, rdata, data, sizeof(data));
				break;
			case ns_t_aaaa:
				if (rdlen == NS_IN6ADDRSZ)
					inet_ntop(AF_INET6, rdata, data, sizeof(data));
				break;
			case ns_t_txt:
				int len = *rdata++;
				strncpy(data, rdata, len);
				data[len] = 0;
				break;
			default:
				break;
			}
			printf("%s: %5s %s [%s] ttl %ds\n",
			       name,
			       type_name(ns_rr_type(rr)),
			       ns_rr_name(rr),
			       data,
			       ns_rr_ttl(rr));
		}
	}
	return 0;
}

static int process_event(void *ctx, void *data, size_t len)
{
	if (sizeof(struct dns_event) > len) {
		fprintf(stderr, "Message too short, discarding\n");
		return 1;
	}
	struct dns_event *event = (struct dns_event *) data;
	double latency_ms = ((double)event->duration) / 1000000;
	fprintf(stderr, "Received dns event id=%04x flags=%04x latency=%.3fms\n",
		event->id, event->flags, latency_ms);

	ns_msg msg;
	int err = ns_initparse(event->payload, event->length, &msg);
	if (err) {
		perror("ns_initparse");
		return 1;
	}
	printf("%s – q: %d, a: %d, ns: %d, ar: %d, rcode: %s\n",
	       ns_msg_getflag(msg, ns_f_qr) ? "R" : "Q",
	       ns_msg_count(msg, ns_s_qd),
	       ns_msg_count(msg, ns_s_an),
	       ns_msg_count(msg, ns_s_ns),
	       ns_msg_count(msg, ns_s_ar),
	       rcode_name(ns_msg_getflag(msg, ns_f_rcode)));

	print_records(true, &msg, " Q", ns_s_qd);
	print_records(false, &msg, " A", ns_s_an);
	print_records(false, &msg, "NS", ns_s_ns);
	print_records(false, &msg, "AR", ns_s_ar);

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

	/* Load and verify BPF object file */
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
