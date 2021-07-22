// SPDX-License-Identifier: GPL-2.0-only
/*
*
* SNAPPY Linux Security Module
*
* Author: Maxime Bélair <maxime.belair@orange.com>
*
* Copyright (C) 2020 - 2021 Orange
*/
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
// 1/ Add a type hook
// 2/ generate functions
// 3/ ???
// 4/ Profit

int lsmpp_bprm_check_security(struct linux_binprm* bprm,
		 void** argv, void** envp) {
	struct lsmpp_ctx ctx = { .bprm_ctx = { .bprm = bprm, .argv = argv, .envp = envp }};	 // state is initialized in lsmpp_run_progs
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
int lsmpp_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen) {
	struct lsmpp_ctx ctx = { .socket_ctx = { .sock=sock, .address=address, .addrlen = addrlen, }};
    return lsmpp_run_progs(SOCKET_CONNECT, &ctx);
}


int lsmpp_ptrace_access_check(struct task_struct *child, unsigned int mode) {
    struct lsmpp_ctx ctx = { .ptrace_child_ctx = { .child = child, .mode = mode, }};
    return lsmpp_run_progs(PTRACE_ACCESS_CHECK, &ctx);
}
int lsmpp_ptrace_traceme(struct task_struct *parent) {
    struct lsmpp_ctx ctx = { .task_ctx = { .task = parent }};
    return lsmpp_run_progs(PTRACE_TRACEME_HOOK, &ctx);
}
int lsmpp_task_prctl(int option, unsigned long arg2, unsigned long arg3,
               unsigned long arg4, unsigned long arg5) {
    struct lsmpp_ctx ctx = { .prctl_ctx = { .option = option, .arg2 = arg2, .arg3 = arg3, .arg4 = arg4, .arg5 = arg5, }};
    return lsmpp_run_progs(TASK_PRCTL, &ctx);
}
void lsmpp_task_free(struct task_struct *task) {
    //struct lsmpp_ctx ctx = { .task_ctx = { .task = task}};
    //return lsmpp_run_progs(TASK_FREE, &ctx);
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
/*
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

*/
// TODO: Work this RCU thing out
int lsmpp_run_progs(enum LSMPP_HOOK_TYPE t, struct lsmpp_ctx *ctx) {
    struct bpf_prog_array_item *item;
    struct bpf_prog *prog;
    int ret, retval = 0;
    //struct list_head* list_it;
	struct lsmpp_namespace* ns;
	
	get_lsmpp_ns(current->nsproxy->lsmpp_ns);
	ns = current->nsproxy->lsmpp_ns;
    preempt_disable();
    rcu_read_lock();
	do {
		if(!ns->progs[t])
			continue;
    	item = rcu_dereference(ns->progs[t])->items;
		while((prog = READ_ONCE(item->prog))) {
			ctx->state = ns->state; // setup state.
			ret = BPF_PROG_RUN(prog, ctx);
			ns->state = ctx->state; // upate state
			if(ret != 0) {
				retval = ret;
				goto out;
			}
			++item;
		}
	} while((ns = ns->parent) != NULL);	
out:
    rcu_read_unlock();
    preempt_enable();
	put_lsmpp_ns(current->nsproxy->lsmpp_ns);
    if(ret != 0 && !IS_ENABLED(CONFIG_SECURITY_LSMPP_ENFORCE)) {
        pr_err("[COMPLAIN] The operation would have been denied"); // TODO: add extra information about the context)
        return 0;
    }
    else return retval;
}

#endif
