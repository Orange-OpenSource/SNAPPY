// SPDX-License-Identifier: GPL-2.0-only
/*
*
* SNAPPY Linux Security Module
*
* Author: Maxime Bélair <maxime.belair@orange.com>
*
* Copyright (C) 2020 - 2021 Orange
*/
#include <uapi/linux/bpf.h>
#include <uapi/linux/ip.h>
#include "bpf_helpers.h"
#include "lsmpp_helpers.h"
#include <linux/socket.h>

SEC("lsmpp")
int my_main(void* ctx) {

	char binname[] = "flatpak-spawn";
	void* argsbinname[] = {(void*)1, binname};


	char forbiddenEnv[] = "LD_LIBRARY_PATH;LD_PRELOAD;LD_AUDIT;LD_DEBUG;LD_DEBUG_OUTPUT;LD_DYNAMIC_WEAK;LD_ORIGIN_PATH;LD_PROFILE_OUTPUT;LD_SHOW_AUXV;LD_USE_LOAD_BIAS;";
	char from[] = "--env=";
	char to[] = "=";

	if(	lsmpp_dynamic_call(ctx, 0, 2, argsbinname) != 1) 			// If prgm is not flatpak-spawn
		return 0;													// It's OK
	void* args_match_env[] = {(void*)-1, forbiddenEnv, (void*) from, (void*) to};
	if(lsmpp_dynamic_call(ctx, 0, 4, args_match_env) >= 0)		// Then we try to match forbidden vars
		return -1; // DENIED
	return 0; // ALLOWED

}
char _license[] SEC("license") = "GPL";
