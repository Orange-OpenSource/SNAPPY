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
#include <linux/socket.h>

SEC("lsmpp")
int my_main(void* ctx) {
	char regex[] = "*[!\\\\]\\\\";
	void* args[2] = {(void*)-1, regex};

	char tofind[] = "\\";
	void* argsstrcmp[2] = {(void*)-1, tofind};

	char binname[] = "sudo";
	void* argsbinname[3] = {(void*)1, binname};



	if(		lsmpp_dynamic_call(ctx, 0, 2, argsbinname) == 1 &&( 	// If prgm is sudo
			lsmpp_dynamic_call(ctx, 0, 0, args) == 1		||	// And args finishes by a single '\'
			lsmpp_dynamic_call(ctx, 0, 1, argsstrcmp) == 1)) 	// Or just is '\' (note could be merged w/ previous regex)
		return -1; // DENIED
	return 0; // ALLOWED

}
char _license[] SEC("license") = "GPL";
