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
#include "snappy_helper_linker.h"

SEC("lsmpp")
int my_main(void* ctx) {	
	//void* args[2] = {(void*)-1, "*\\$"};
	//return snappy_helper(CVE_2019_5736, 1eaad09fe550a98fba28ebe048854ccdc81b8a60d36768bc32e470b33d49b560, 0,  ctx, ctx);
	lsmpp_dynamic_call(ctx, 0, 0, ctx);
	return 0;
}
char _license[] SEC("license") = "GPL";
