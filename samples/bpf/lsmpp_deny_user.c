// SPDX-License-Identifier: GPL-2.0-only
/*
*
* SNAPPY Linux Security Module
*
* Author: Maxime Bélair <maxime.belair@orange.com>
*
* Copyright (C) 2020 - 2021 Orange
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <assert.h>
#include <linux/limits.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include "bpf/libbpf.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/resource.h>

#include "perf-sys.h"
#include "trace_helpers.h"
#include "lsmpp_helpers.h"

#define LSMPP_PATH_MAX 64

//#define LSM_HOOK_PATH_BASE "/sys/kernel/security/lsmpp/policies/"
#define LSM_HOOK_PATH_BASE "/mnt/lsmpp/"

int main(int argc, char **argv)
{
	struct bpf_object *prog_obj;
	struct bpf_prog_load_attr attr;
	int prog_fd, target_fd;
	int ret;
	char filename[LSMPP_PATH_MAX], hook_path[LSMPP_PATH_MAX];

	if (argc != 2) {
		errx(EXIT_FAILURE, "Usage %s LSMPP_HOOK\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	memset(&attr, 0, sizeof(struct bpf_prog_load_attr));
	attr.prog_type = BPF_PROG_TYPE_LSMPP;
	attr.expected_attach_type = BPF_LSMPP;
	attr.file = filename;
	sprintf(hook_path, "%s%s", LSM_HOOK_PATH_BASE, argv[1]);

	/* Attach the BPF program to the given hook */
	target_fd = open(hook_path, O_RDWR);

	if (target_fd < 0)
		err(EXIT_FAILURE, "Failed to open target file");

	if (bpf_prog_load_xattr(&attr, &prog_obj, &prog_fd))
		err(EXIT_FAILURE, "Failed to load eBPF program");

	ret = bpf_prog_attach(prog_fd, target_fd, BPF_LSMPP, 0);
	if (ret < 0)
		err(EXIT_FAILURE, "Failed to attach prog to LSM hook");
	return EXIT_SUCCESS;
}
