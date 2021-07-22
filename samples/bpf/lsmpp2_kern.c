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


#define MAX_CPUS 128

#define _(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})
/*

struct bpf_map_def SEC("maps") env_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct lsmpp_env_value),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") perf_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(u32),
	.max_entries = MAX_CPUS,
};
*/
SEC("lsmpp")
int test_dynamic_call(void* ctx) {
		u64 times_ret;
	s32 ret;
	u32 map_id = 0;
	char *map_value;
	struct lsmpp_env_value *env;
	//env = bpf_map_lookup_elem(&env_map, &map_id);
	//if (!env)
	//	return -ENOMEM;
//	char test[] = "It works! ;)";
//	void* args[] = {/*(void*)test, (void*) 2*/};

	/*
	if(env->name == NULL)
		return 1;
	env->name[0] = 'f';
	env->name[1] = '\0';
	*/
	//lsmpp_dynamic_call(ctx, 0, 0, args);
//	unsigned int fun_ret =  lsmpp_dynamic_call(ctx, 0, 0, args);
	return 0;
	/*_dynamic_call(
			ctx,
			"test",
			1,
		       	NULL
	);*/
	/*env->name[0] = 'f';
	env->name[1] = '\0';
	env->value[0] ='f';
	env->value[1] = '\0';
	times_ret = 1;
	lsmpp_get_env_var(ctx, env->name, ENV_VAR_NAME_MAX_LEN,
				     env->value, ENV_VAR_VAL_MAX_LEN);
	ret = __LOWER(times_ret);
	if (ret == -E2BIG)
		env->overflow = true;
	else if (ret < 0)
		return ret;

	if(env->value[0] == 'n' && env->value[1] == 'o')
		return -1;
	env->times = __UPPER(times_ret);
	env->p_pid = fun_ret; // bpf_get_current_pid_tgid();
	bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, env,
			      sizeof(struct lsmpp_env_value));
i*/
//	bpf_trace_printk("hey!\n",5);
	return 0;
/*
	
	
	
	u64 times_ret;
	s32 ret;
	u32 map_id = 0;
	char *map_value;
	struct lsmpp_env_value *env;
	struct lsmpp_bprm_ctx c = ctx->bprm_ctx;
	if(&c == NULL || c.num_arg_pages<0) return 1;
	int num_args = c.num_arg_pages;
	return 2;
	
	if(ctx == NULL || &((struct lsmpp_ctx*)ctx)->bprm_ctx == NULL)
		return -4;
	else{
		//return ctx->bprm_ctx.bprm;
		//if(rpm == NULL)
		//	return 1;
		char *filename = rpm->filename;
		if(!filename)
			return -2;
		if(filename[0] == 'd' && filename[1] == 'e' ) {
			return -3;
		}*/
	//return 3;
	//}
}

char _license[] SEC("license") = "GPL";
