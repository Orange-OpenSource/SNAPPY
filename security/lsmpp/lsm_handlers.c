#ifndef LSM_HANDLERS
#define LSM_HANDLERS

#include <linux/lsm_hooks.h>
#include <linux/filter.h> // For BPF_PROG_RUN macro
#include <linux/pid_namespace.h>
#include "lsmpp.h"

#include <linux/binfmts.h>
#include <linux/cred.h>

//#include "lsm_handlers.h"

// TODO Automate the generation of these helpers? Difficulty: type depends of the helper
int lsmpp_bprm_check_security(struct linux_binprm* bprm) {
	struct lsmpp_ctx ctx = { .bprm_ctx = { .bprm = bprm }};	
/*	struct task_struct* curr = current;
	pr_debug("Running bprm check secu task uid=%d ; %d ; curent = %p", bprm->cred->uid.val, current->pid, current);

	do {
		pr_debug("=> Parent pid = %d", curr->pid);
	} while(curr->pid > 1 && (curr = curr->parent) != NULL);
	*/
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

// Note: Linux uses PID recycling! This means that a process cannot be **reliably** be reliably identified only using a pid
// Be very careful to always keep that in mind to avoid attacks!
// If we delete the policy related to a process when it is destroyed (without race condition), we shoulde avoid the following attack:
// 		The system creates a policy to a process pid. then spawn dummy process to loop the pid counter to pid-x (x small) 
//		then delete the process. If the process gets recycled by the victim, it can briefly execute the policies of the older one (race cond!)
bool is_visible(struct pid_namespace* pid_ns, int policy_pid, struct task_struct* curr) {
//remplacer curr => curr->parent par var tmp
	struct pid_namespace* current_pidns = task_active_pid_ns(current);
	struct task_struct *ns_creator;
	if(pid_ns == current_pidns) { // direct ptr cmp should be fine	
		do {
			if(curr->pid == policy_pid) {
				pr_debug("Hooray, found matching pol for pid=%d, matching pol=%d\n", curr->pid, policy_pid);
				return true;
			}
		} while(curr->parent->pid > 0 && (curr = curr->parent) != NULL);
	}
	else do { // TODO: faire différemment Algo. Prendre le pid global à partir du pid dans la ns
		if(pid_ns == current_pidns) {
			ns_creator = current_pidns->child_reaper;
			pr_debug("Found a Namespace child of the process %d", ns_creator->pid);
			do {
				if(ns_creator->pid == policy_pid) {
					pr_debug("Found process responsible for pid %d for ns %p created by %p", policy_pid, current_pidns,  ns_creator);
					return true;
				}
				else pr_debug("creator not (yet) found => pid=%d, tofind=%d", ns_creator->pid, policy_pid);
			} while(ns_creator->parent->pid > 0 && (ns_creator = ns_creator->parent) != NULL);
			return false; // Not found
		}
		else pr_debug("Not found in namespace %p", current_pidns);
	} while(current_pidns->level > 0 && (current_pidns = current_pidns->parent) != NULL);
	return false;
}


// TODO: Work this RCU thing out
int lsmpp_run_progs(enum LSMPP_HOOK_TYPE t, struct lsmpp_ctx *ctx) {
    struct bpf_prog_array_item *item;
    struct bpf_prog *prog;
    struct lsmpp_hook *h = &lsmpp_hook_array[t];
    int ret, retval = 0;
    struct list_head* list_it;
	struct lsmpp_helper_ctx* entry;

    preempt_disable();
    rcu_read_lock();

    // This condition avoid LSMPP to crash when the program are not yet allocated.
    // TODO: Is this something we want? Should we wait that LSMPP is fully initialized to use the kernel(leading to more latency) or be unprotected at early moments?
    if(h->progs == NULL) {
        goto out;
    }
    item = rcu_dereference(h->progs)->items;
    list_it = &h->helper_ctx_list; // TODO todo we do not add verification of coherency. is it necessary?
	
	list_for_each_entry(entry, list_it, list) {
		prog = READ_ONCE(item->prog);
		if(!prog) {
			pr_err("WTF? prog == null");
			return 0;
		}
		if(is_visible(entry->pidns, entry->pid, current)) {
			pr_debug("Policy found! :)");
			ret = BPF_PROG_RUN(prog, ctx);
			if(ret != 0) {
				retval = ret;
				goto out;
			}
		}
		else
			pr_debug("No policy");
		item++;
	}
	
/*
	while ((prog = READ_ONCE(item->prog))) {
		// TODO Check the visibility of the BPF code
		if(is_visible(list_entry(&list_it, struct lsmpp_helper_ctx, list), current)) {
			ret = BPF_PROG_RUN(prog, ctx);
			if (ret != 0) {
            	retval = ret;
				goto out;
        	}
        	item++;
    	    list_it = list_it->next;
		}
		else {
			pr_debug(">> Nope, policy NOK");
		}
	}
*/
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
