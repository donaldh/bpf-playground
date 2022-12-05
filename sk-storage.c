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
#include <sys/stat.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <netinet/tcp.h>
#include <bpf/bpf.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <netdb.h>

#include "sk-storage.skel.h"
#include "sk-storage.h"

static struct env {
	bool verbose;
} env = { 0 };

const char *argp_program_version = "sk-storage 0.0";
const char *argp_program_bug_address = "<donald.hunter@redhat.com>";
const char argp_program_doc[] =
"BPF sk-storage demo application.\n"
"\n"
"Trace socket operations.\n"
"\n"
"USAGE: ./sk-storage [-v]\n";

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

const char *foo = "/sys/fs/cgroup/foo";
const char *foo_procs = "/sys/fs/cgroup/foo/cgroup.procs";

static void join_cgroup()
{
	if (mkdir(foo, 0777) && errno != EEXIST) {
		fprintf(stderr, "Failed to create cgroup %s\n", foo);
		exit(1);
	}

	int fd = open(foo_procs, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s\n", foo_procs);
		exit(1);
	}

	pid_t pid = getpid();
	if (dprintf(fd, "%d\n", pid) < 0) {
		fprintf(stderr, "Failed to add %d to %s\n", pid, foo_procs);
		exit(1);
	}

	close(fd);
}

static int get_cgroup() {
	int fd = open(foo, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open cgroup %s\n", foo);
		exit(1);
	}
	return fd;
}

static void send_byte(int fd)
{
	char b = 0x55;

	write(fd, &b, sizeof(b));
}

static int wait_for_ack(int fd, int retries)
{
	struct tcp_info info;
	socklen_t optlen;
	int i, err;

	for (i = 0; i < retries; i++) {
		optlen = sizeof(info);
		err = getsockopt(fd, SOL_TCP, TCP_INFO, &info, &optlen);
		if (err < 0) {
			fprintf(stderr, "Failed to lookup TCP stats\n");
			return err;
		}
		if (info.tcpi_unacked == 0)
			return 0;

		usleep(10);
	}

	fprintf(stderr, "Did not receive ACK\n");
	return -1;
}

static int client_connect(const char* host, const char* service) {
    int sock;

    struct addrinfo hints;
    struct addrinfo *result, *rp;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* TCP socket */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;           /* Any protocol */

    int status = getaddrinfo(host, service, &hints, &result);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        exit(EXIT_FAILURE);
    }

    /* getaddrinfo() returns a list of address structures.
       Try each address until we successfully connect(2).
       If socket(2) (or connect(2)) fails, we (close the socket
       and) try the next address. */

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        //print_addr(rp);

        sock = socket(rp->ai_family, rp->ai_socktype,
                      rp->ai_protocol);
        if (sock == -1)
            continue;

        if (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1)
            break;                  /* Success */

        close(sock);
    }

    freeaddrinfo(result);           /* No longer needed */

    if (rp == NULL) {               /* No address succeeded */
	    fprintf(stderr, "Could not connect to %s:%s\n", host, service);
	    return -1;
    }

    return sock;
}

static void output(int map_fd, int client_fd)
{
	struct tcp_metrics val;

	int err = bpf_map_lookup_elem(map_fd, &client_fd, &val);
	if (err) {
		fprintf(stderr, "Failed to lookup sk_storage\n");
		return;
	}

	printf("invoked=%d, dsack_dups=%d, delivered=%d, delivered_ce=%d, icsk_retransmits=%d\n",
	       val.invoked, val.dsack_dups, val.delivered, val.delivered_ce, val.icsk_retransmits);
}

int main(int argc, char **argv)
{
	struct sk_storage_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	join_cgroup();

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = sk_storage_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = sk_storage_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach cgroup */
	int prog_fd = bpf_program__fd(skel->progs._sockops);
	int map_fd = bpf_map__fd(skel->maps.socket_storage);
	int cgroup_fd = get_cgroup();
	err = bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0);
	if (err) {
		fprintf(stderr, "Failed to attach program to cgroup %s\n", foo);
		goto cleanup;
	}

	int client_fd = client_connect("localhost", "3456");
	if (client_fd < 0) {
		fprintf(stderr, "Failed to open inet socket\n");
		fprintf(stderr, "\n");
		fprintf(stderr, "Run socat -v tcp-l:3456,fork exec:'/bin/cat' as an echo server.\n");
		fprintf(stderr, "\n");
		goto cleanup;
	}

	struct tcp_metrics value = { };
	err = bpf_map_update_elem(map_fd, &client_fd, &value, BPF_ANY);
	if (err) {
		fprintf(stderr, "Failed to create elem: %s\n", strerror(-err));
		goto cleanup;
	}

	err = bpf_map_delete_elem(map_fd, &client_fd);
	if (err) {
		fprintf(stderr, "Failed to update elem: %s\n", strerror(-err));
		goto cleanup;
	}

	int i = 0;
	while (i++ < 2) {
		send_byte(client_fd);
		if (wait_for_ack(client_fd, 100) < 0) {
			goto cleanup;
		}
		output(map_fd, client_fd);
	}

cleanup:
	/* Clean up */
	sk_storage_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
