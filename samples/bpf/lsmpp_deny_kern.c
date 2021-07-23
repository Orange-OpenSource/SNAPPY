// SPDX-License-Identifier: GPL-2.0-only
/*
*
* SNAPPY Linux Security Module
*
* Author: Maxime Bélair <maxime.belair@orange.com>
*
* Copyright (C) 2020 - 2021 Orange
*/

#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/ip.h>
#include "bpf_helpers.h"
#include "lsmpp_helpers.h"

SEC("lsmpp")
int my_main(void* ctx) {
	return -1;
}
char _license[] SEC("license") = "GPL";
