// SPDX-License-Identifier: GPL-2.0-only
/*
*
* SNAPPY Linux Security Module
*
* Author: Maxime Bélair <maxime.belair@orange.com>
*
* Copyright (C) 2020 - 2021 Orange
*/
/// Handling of eBPF helpers-related operations

#include <linux/slab.h>
#include <linux/printk.h>
#include <crypto/hash.h>

#include "snappy.h"

BPF_CALL_4(snappy_dynamic_call, struct snappy_ctx*, ctx, int, lib_id, u16, fun_id, void**, args) {

    struct bpf_helper helper;
    int (*dyn_func)(struct snappy_ctx* ctx, void* args[]);
    int fn_ret;

    if(lib_id < 0 || lib_id >= helper_array.number) {
		pr_info("Error, trying to call inexistant lib id=%d/%d\n", lib_id, fun_id);
        return -1;
    }

    helper = helper_array.helpers[lib_id];

	if(fun_id < 0 || fun_id >= helper.nb_helpers) {
		pr_info("error, trying to call inexistant lib id=%d/%d\n", lib_id, fun_id);
		return -1;
	}

    dyn_func = (void*)(helper.helper + helper.entrypoints[fun_id]);

	//pr_debug("Ready to call func from BPF, (1st arg = %s)\n", args?(char*) args[0]:"none");
    fn_ret = dyn_func(ctx, args);
	//pr_debug("Done, result = %d\n", fn_ret);
    return fn_ret;
}

const struct bpf_func_proto snappy_dynamic_call_proto = {
    .func = snappy_dynamic_call,
    .gpl_only = true,
    .ret_type = RET_INTEGER,
    .arg1_type = ARG_PTR_TO_CTX, //ARG_PTR_TO_CTX,
    .arg2_type = ARG_ANYTHING, // integer
    .arg3_type = ARG_ANYTHING, // integer
    .arg4_type = ARG_DONTCARE, //ARG_PTR_TO_MEM,
};


//Currently, when the size of the array must be increased, we simply try to double it.
static int increase_array(void** arr, int old_sz, int new_sz) {
	void* new_arr = __vmalloc_node_range(new_sz, 1, VMALLOC_START, VMALLOC_END,
			GFP_KERNEL, PAGE_KERNEL_EXEC, VM_FLUSH_RESET_PERMS,
			NUMA_NO_NODE, __builtin_return_address(0)); 
	if(new_arr == NULL)
		return -1;
	new_arr = memcpy(new_arr, arr, old_sz);
	vfree(arr); // TODO use locks to prevent uses of this freed var by other threads.
	return 0;

}
static struct crypto_shash *snappy_tfm;

char *compute_hash(struct bpf_helper* helper, int got_offset, int got_size)
{
	SHASH_DESC_ON_STACK(desc, snappy_tfm);
	char *hash = NULL;
	int error = -ENOMEM;

	if (!snappy_tfm)
		return NULL;

	hash = kzalloc(crypto_shash_digestsize(snappy_tfm), GFP_KERNEL);
	if (!hash) goto fail;

	desc->tfm = snappy_tfm;

	error = crypto_shash_init(desc);
	if (error) goto fail;
		
	#define updatehash(x, sz) 	error = crypto_shash_update(desc, (u8*)(x), sz);\
								if(error) goto fail;
	
	updatehash(helper->name, strlen(helper->name));
	updatehash(helper->entrypoints, helper->nb_helpers*sizeof(helper->entrypoints[0]));
	updatehash(helper->helper, got_offset);
	updatehash(((u8*)helper->helper) + got_offset + got_size, helper->code_size - got_offset - got_size);


	error = crypto_shash_final(desc, hash);
	if(error) goto fail;
	#undef updatehash
	return hash;

fail:
	kfree(hash);
	return NULL;
}

int add_bpf_helper(struct bpf_helper_array* arr, struct bpf_helper helper) {
	int newsz;
	if(arr->size + helper.code_size > arr->maxsize) { // We check that we don't go beyond our memory limits
			// NOTE: For now we only deny the helper addition? We could also to prune some helper of our ''cache''
			return -1;
	}

	if(arr->number + 1 >= arr->maxnumber) {	// If the array is full we increase it.
		// TODO: add constrainsts to check wether the size is beyond some limits.
		newsz = increase_array_strategy(arr->number);
		if(increase_array((void**) &arr->helpers, arr->size, newsz) == 0)
			arr->maxnumber = newsz;
		else // can't increase array
			return -1;
	}
	arr->helpers[arr->number] = helper;
	arr->size += helper.code_size;
	arr->number++;
	return 0;
}
// To be implemented
int del_bpf_helper(struct bpf_helper_array* arr, int idx) {
	return -1;
}
struct bpf_helper new_bpf_helper(struct mmap_info* info, int code_size) {
	struct bpf_helper helper;
	unsigned long int* got_entry;
	int idx;
	helper.code_size 	= code_size;
	helper.entrypoints  = info->entrypoints;
	helper.nb_helpers   = info->nb_helpers;
	helper.name			= info->name;
	helper.helper 		= __vmalloc_node_range(code_size, 1, VMALLOC_START, VMALLOC_END,
			GFP_KERNEL, PAGE_KERNEL_EXEC, VM_FLUSH_RESET_PERMS,
			NUMA_NO_NODE, __builtin_return_address(0));

	memcpy(helper.helper, info->data /*+ info->code_offset*/, code_size);

	helper.hash 		= compute_hash(&helper, info->got_offset, info->got_size);
	/* If kaslr is enabled, we patch all external symbols in the got
	   by adding the kaslr offset */
	if(!helper.hash) { pr_err("Cant compute hash"); }
	pr_info("Hash of new helper begin by %02x%02x %02x%02x\n", helper.hash[0],helper.hash[1],helper.hash[2],helper.hash[3]);
	#ifdef CONFIG_RANDOMIZE_BASE
	printk(KERN_INFO "Lets update offsets kaslr offset= %lx, got_offset=%lx\n", get_kaslr_offset(), (unsigned long)(helper.helper + info->got_offset ));
    if(info->got_offset) {
        for(	got_entry = helper.helper + info->got_offset, idx=0 ;
			 	idx * sizeof(unsigned long*) < info->got_size;
				++idx  
		) {
			if(got_entry[idx] >=0xffffffff80000000) { // if in the kernel
	            printk(KERN_INFO "Index %x goes from %lx to %lx\n", idx, (unsigned long)got_entry[idx], (unsigned long)(got_entry[idx] + get_kaslr_offset()));
    	        got_entry[idx] += get_kaslr_offset();
			}
    	}
	}

	#endif
	// TODO: Check that the helper has not already be loaded in the kernel.
	return helper;
}
int  __init init_bpf_helpers(void) {
//	struct bpf_helper_array arr;
	
	snappy_tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(snappy_tfm)) 
		pr_err("failed to init sha256 algorithm. SNAPPY will not work!\n");
	helper_array.number 	= 0;
	helper_array.maxnumber	= INITIAL_BPF_ARRAY_NUMBER;
	helper_array.size 	= 0;
	helper_array.maxsize	= BPF_ARRAY_MAX_SIZE;
	helper_array.helpers	= vmalloc(INITIAL_BPF_ARRAY_NUMBER * sizeof(struct bpf_helper));

	return 0;
}


void debug_print_helpers(struct bpf_helper_array arr) {
	int i;
	printk(KERN_INFO "-- Helpers Array: %d/%d items, size=%lld/%lld --\n", arr.number, arr.maxnumber, arr.size, arr.maxsize);
	for(i=0; i<min((uint32_t)8,arr.number); ++i) {
		if(arr.helpers[i].code_size <=0)
			printk(KERN_INFO "helper[%d] size < 0\n", i);
		else if(arr.helpers[i].entrypoints[0] + 16 > arr.helpers[i].code_size)	
			printk(KERN_INFO "helper[%d] too small to be displayed\n", i);
		else
			printk(KERN_INFO "helper[%d] start at off %d by %llx %llx\n",
					i, arr.helpers[i].entrypoints[0], ((uint64_t*)(arr.helpers[i].helper +arr.helpers[i].entrypoints[0]))[0], ((uint64_t*)(arr.helpers[i].helper +arr.helpers[i].entrypoints[0]))[1]);
	}
}

late_initcall(init_bpf_helpers);
