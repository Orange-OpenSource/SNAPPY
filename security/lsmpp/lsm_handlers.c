#ifndef LSM_HANDLERS
#define LSM_HANDLERS

#include <linux/lsm_hooks.h>
#include <linux/filter.h> // For BPF_PROG_RUN macro
#include "lsmpp.h"
//#include "lsm_handlers.h"

// TODO Automate the generation of these helpers? Difficulty: type depends of the helper
int lsmpp_bprm_check_security(struct linux_binprm* bprm) {
	struct lsmpp_ctx ctx = { .bprm_ctx = { .bprm = bprm }};
	return lsmpp_run_progs(BPRM_CHECK_SECURITY, &ctx);
}
int lsmpp_file_open(struct file* file) {
    struct lsmpp_ctx ctx = { .file_ctx = { .file = file }};
    return lsmpp_run_progs(FILE_OPEN, &ctx);
}
int lsmpp_mmap_file(struct file* file, unsigned long reqprot, unsigned long prot, unsigned long flags) {
	struct lsmpp_ctx ctx = { .mmap_ctx = { .reqprot=reqprot, .file=file, .prot = prot, .flags = flags}};
	return lsmpp_run_progs(MMAP_FILE, &ctx);
}

/*
struct security_hook_list* get_lsm_hook_from_type(enum LSMPP_HOOK_TYPE t) {
	struct security_hook_list* h = kmalloc(sizeof(struct security_hook_list), GFP_KERNEL);
	switch(t) {
	#define LSMPP_HOOK_INIT(lsmpp, lsm) 			\
		case lsmpp:									\
			h[0].head = &security_hook_heads. lsm;	\
			h[0].hook. lsm = &lsmpp_##lsm;			\
			break;

	#include "hooks.h"
	#undef LSMPP_HOOK_INIT
	default:
		pr_err("Trying to access inexistant hook n°%d", t);
		h=NULL;
	}
	return h;
	
	
}
*/
// TODO: Work this RCU thing out.
int lsmpp_run_progs(enum LSMPP_HOOK_TYPE t, struct lsmpp_ctx *ctx) {
    struct bpf_prog_array_item *item;
    struct bpf_prog *prog;
    struct lsmpp_hook *h = &lsmpp_hook_array[t];
    int ret, retval = 0;
    struct list_head* list_entry;
    preempt_disable();
    rcu_read_lock();

    // This condition avoid LSMPP to crash when the program are not yet allocated.
    // TODO: Is this something we want? Should we wait that LSMPP is fully initialized to use the kernel(leading to more latency) or be unprotected at early moments?
    if(h->progs == NULL) {
        goto out;
    }
    item = rcu_dereference(h->progs)->items;
    list_entry = (&h->helper_ctx_list)->next; // TODO todo we do not add verification of coherency. is it necessary?
    while ((prog = READ_ONCE(item->prog))) {
        // TODO Check the visibility of the BPF code
        ret = BPF_PROG_RUN(prog, ctx);
        if (ret != 0) {
            retval = ret;
            goto out;
        }
        item++;
        list_entry = list_entry->next;
    }

out:
    rcu_read_unlock();
    preempt_enable();
    if(!IS_ENABLED(CONFIG_SECURITY_LSMPP_ENFORCE)) {
        pr_err("[COMPLAIN] The operation would have been denied"); // TODO: add extra information about the context)
        return 0;
    }
    else return retval;
}

#endif
