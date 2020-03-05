/// Handling of eBPF helpers-related operations

#include <linux/slab.h>
#include <linux/printk.h>

#include "lsmpp.h"

BPF_CALL_4(lsmpp_dynamic_call, struct lsmpp_ctx*, ctx, int, lib_id, u16, fun_id, void**, args) {

    struct bpf_helper helper;
    int (*dyn_func)(void* args[]);
    int fn_ret;

    if(lib_id < 0 || lib_id >= helper_array.number) {
        printk(KERN_INFO "ERROR, trying to call inexistant lib id=%d/%d\n", lib_id, fun_id);
        return -1;
    }

    helper = helper_array.helpers[lib_id];
    dyn_func = (void*)(helper.helper + helper.offset);
//todel printk(KERN_INFO "Ready to call func from BPF, (1st arg = %s)\n", args?(char*) args[0]:"none");
    fn_ret = dyn_func(args);
//todel printk(KERN_INFO "Done, result = %d\n", fn_ret);
    return fn_ret;
}

const struct bpf_func_proto lsmpp_dynamic_call_proto = {
    .func = lsmpp_dynamic_call,
    .gpl_only = true,
    .ret_type = RET_INTEGER,
    .arg1_type = ARG_PTR_TO_CTX, //ARG_PTR_TO_CTX,
    .arg2_type = ARG_ANYTHING, // integer
    .arg3_type = ARG_ANYTHING, // integer
    .arg4_type = ARG_DONTCARE, //ARG_PTR_TO_MEM,
};


//Currently, when the size of the array must be increased, we simply try to double it.
static inline int increase_array(void** arr, int old_sz, int new_sz) {
	void* new_arr = __vmalloc(new_sz, GFP_KERNEL, PAGE_KERNEL_EXEC);
	if(new_arr == NULL)
		return -1;
	new_arr = memcpy(new_arr, arr, old_sz);
	vfree(arr); // TODO use locks to prevent uses of this freed var by other threads.
	return 0;

}

inline int add_bpf_helper(struct bpf_helper_array* arr, struct bpf_helper helper) {
	int newsz;
	if(arr->size + helper.size > arr->maxsize) { // We check that we don't go beyond our memory limits
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
	arr->size += helper.size;
	arr->number++;
	return 0;
}
// To be implemented
inline int del_bpf_helepr(struct bpf_helper_array* arr, int idx) {
	return -1;
}
inline struct bpf_helper new_bpf_helper(void* tocopy, uint32_t sz, uint32_t offset) {
	struct bpf_helper helper;
	helper.size 	= sz;
	helper.offset	= offset;
	helper.helper 	= __vmalloc(sz, GFP_KERNEL, PAGE_KERNEL_EXEC);
	memcpy(helper.helper, tocopy, sz);
	return helper;
}
inline struct bpf_helper_array new_bpf_helper_array(void) {
	struct bpf_helper_array arr;
	arr.number 	= 0;
	arr.maxnumber 	= INITIAL_BPF_ARRAY_NUMBER;
	arr.size 	= 0;
	arr.maxsize	= BPF_ARRAY_MAX_SIZE;
	arr.helpers	= vmalloc(INITIAL_BPF_ARRAY_NUMBER * sizeof(struct bpf_helper));
	return arr;
}

void debug_print_helpers(struct bpf_helper_array arr) {
	int i;
	printk(KERN_INFO "-- Helpers Array: %d/%d items, size=%lld/%lld --\n", arr.number, arr.maxnumber, arr.size, arr.maxsize);
	for(i=0; i<min((uint32_t)8,arr.number); ++i) {
		if(arr.helpers[i].size <=0)
			printk(KERN_INFO "helper[%d] size < 0\n", i);
		else if(arr.helpers[i].offset + 16 > arr.helpers[i].size)
			printk(KERN_INFO "helper[%d] too small to be displayed\n", i);
		else
			printk(KERN_INFO "helper[%d] start at off %lld by %llx %llx\n",
				       	i, arr.helpers[i].offset, ((uint64_t*)(arr.helpers[i].helper +arr.helpers[i].offset))[0], ((uint64_t*)(arr.helpers[i].helper +arr.helpers[i].offset))[1]);
	}
}


