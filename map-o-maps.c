// -*- indent-tabs-mode: nil; c-basic-offset: 8; -*-
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Red Hat */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/btf.h>

#include "map-o-maps.skel.h"

#include <bpf/btf.h>

static struct env {
        int interval;
        int device;
        bool verbose;
} env = { 1, 0, 0 };

const char *argp_program_version = "map-o-maps 0.0";
const char *argp_program_bug_address = "<donald.hunter@redhat.com>";
const char argp_program_doc[] =
"USAGE: ./map-o-maps [-v]\n";

static const struct argp_option opts[] = {
        { "interval", 'i', "seconds", 0, "Interval between reports" },
        { "device", 'd', "ifindex", 0, "Device ifindex" },
        { "verbose", 'v', NULL, 0, "Verbose debug output" },
        {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
        switch (key) {
        case 'i':
                env.interval = atoi(arg);
                break;
        case 'd':
                env.device = atoi(arg);
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

int add_devmap(int outer_fd, int index, const char *name) {
        int fd, ret;
        __u32 key, value;

        fd = bpf_map_create(BPF_MAP_TYPE_DEVMAP, name, sizeof(key), sizeof(value), 256, NULL);

        if (fd < 0) {
                fprintf(stderr, "add_devmap for %s returned %d %s\n", name, fd,
                        strerror(-fd));
                return fd;
        }

        ret = bpf_map_update_elem(outer_fd, &index, &fd, BPF_ANY);
        return ret;
}

int main(int argc, char **argv)
{
        struct map_o_maps_bpf *skel;
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
        skel = map_o_maps_bpf__open();
        if (!skel) {
                fprintf(stderr, "Failed to open and load BPF skeleton\n");
                return 1;
        }

        /* Load & verify BPF programs */
        err = map_o_maps_bpf__load(skel);
        if (err) {
                fprintf(stderr, "Failed to load and verify BPF skeleton\n");
                goto cleanup;
        }

        /* Attach tracepoints */
        err = map_o_maps_bpf__attach(skel);
        if (err) {
                fprintf(stderr, "Failed to attach BPF skeleton\n");
                goto cleanup;
        }

        while (!exiting) {
                err = sleep(env.interval);
                /* Ctrl-C will cause -EINTR */
                if (err == -EINTR) {
                        err = 0;
                        continue;
                }

                printf("\033[H\033[JWaiting for Ctrl-C ...\n\n");
        }

cleanup:
        /* Clean up */
        map_o_maps_bpf__destroy(skel);

        return err < 0 ? -err : 0;
}
