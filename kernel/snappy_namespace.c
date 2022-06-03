// SPDX-License-Identifier: GPL-2.0-only
/*
*
* SNAPPY Linux Security Module
*
* Author: Maxime Bélair <maxime.belair@orange.com>
*
* Copyright (C) 2020 - 2021 Orange
*/
#include <linux/export.h>
#include <linux/snappy_namespace.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>
#include <linux/proc_ns.h>
#include <linux/sched/task.h>
#include <linux/capability.h>
#include <linux/cred.h>

/**
 * Clone a new ns copying an original snappy namespace, setting refcount to 1
 * @old_ns: old snappy namespace to clone
 * @user_ns: user namespace that current task runs in
 * Return ERR_PTR(-ENOMEM) on error (failure to kmalloc), new ns otherwise
 */
static struct snappy_namespace *clone_snappy_ns(struct user_namespace *user_ns,
					  struct snappy_namespace *old_ns)
{
	struct snappy_namespace *ns;
	int err;
		
	if(old_ns->level > 32) {
		pr_err("Too much snappy ns\n");
		return ERR_PTR(-EPERM);
	}	

	ns = kmalloc(sizeof(*ns), GFP_KERNEL);
	if (ns)
		kref_init(&ns->kref);
	else
		return ERR_PTR(-ENOMEM);
	err = ns_alloc_inum(&ns->ns);
	if (err) {
		kfree(ns);
		return ERR_PTR(err);
	}
	ns->ns.ops = &snappyns_operations;
	get_snappy_ns(old_ns);	
	ns->level = old_ns->level + 1;
	ns->parent = old_ns;
	ns->user_ns = get_user_ns(user_ns);
	ns->state = 0; // Init
	memset(ns->progs, 0, SNAPPY_HOOK_TYPE_SIZE * sizeof(ns->progs[0]));
	return ns;
}

/**
 * Copy task's snappy namespace, or clone it if flags
 * specifies CLONE_NEWSNAPPY.  In latter case, events
 * in new snappy namespace will be measured against a
 * separate measurement policy and results will be
 * extended into a sparate measurement list
 *
 * @flags: flags used in the clone syscall
 * @user_ns: user namespace that current task runs in
 * @old_ns: old snappy namespace to clone
 */
struct snappy_namespace *copy_snappy_ns(unsigned long flags,
			       struct user_namespace *user_ns,
			       struct snappy_namespace *old_ns)
{
	struct snappy_namespace *new_ns;

	BUG_ON(!old_ns);
	get_snappy_ns(old_ns);

	if (!(flags & CLONE_NEWSNAPPY))
		return old_ns;

	new_ns = clone_snappy_ns(user_ns, old_ns);
	put_snappy_ns(old_ns);

	return new_ns;
}

static void destroy_snappy_ns(struct snappy_namespace *ns)
{
	struct bpf_prog_array_item* item;
	int i;
	for(i=0; i<SNAPPY_HOOK_TYPE_SIZE; ++i) { // We delete the progs stored in the NS
		if(ns->progs[i] == NULL)
			continue;
		for (item = ns->progs[i]->items; item->prog; item++)
			bpf_prog_put(item->prog);
		
		bpf_prog_array_free(ns->progs[i]);
	}

	put_user_ns(ns->user_ns);
	ns_free_inum(&ns->ns);
	kfree(ns);
}

void free_snappy_ns(struct kref *kref)
{
	struct snappy_namespace *ns;
	struct snappy_namespace *parent;

	ns = container_of(kref, struct snappy_namespace, kref);
	parent = ns->parent;
	destroy_snappy_ns(ns);
	put_snappy_ns(parent);
}

static inline struct snappy_namespace *to_snappy_ns(struct ns_common *ns)
{
	return container_of(ns, struct snappy_namespace, ns);
}

static struct ns_common *snappyns_get(struct task_struct *task)
{
	struct snappy_namespace *ns = NULL;
	struct nsproxy *nsproxy;

	task_lock(task);
	nsproxy = task->nsproxy;
	if (nsproxy) {
		ns = nsproxy->snappy_ns;
		get_snappy_ns(ns);
	}
	task_unlock(task);

	return ns ? &ns->ns : NULL;
}

static void snappyns_put(struct ns_common *ns)
{
	put_snappy_ns(to_snappy_ns(ns));
}

static int snappyns_install(struct nsset *nsset, struct ns_common *new)
{
	struct snappy_namespace *ns = to_snappy_ns(new);
	struct snappy_namespace *tmp = ns;

	if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN) ||
	    !ns_capable(current_user_ns(), CAP_SYS_ADMIN)) {
		do {
			if(tmp == nsset->nsproxy->snappy_ns)
				break; // Valid!
			if(tmp == &init_snappy_ns)
				return -EPERM;
			tmp = tmp->parent;
		} while(1);	
	}
	get_snappy_ns(ns);
	put_snappy_ns(nsset->nsproxy->snappy_ns);
	nsset->nsproxy->snappy_ns = ns;
	return 0;
}

const struct proc_ns_operations snappyns_operations = {
	.name    = "snappy",
	.type    = CLONE_NEWSNAPPY,
	.get     = snappyns_get,
	.put     = snappyns_put,
	.install = snappyns_install,
};
