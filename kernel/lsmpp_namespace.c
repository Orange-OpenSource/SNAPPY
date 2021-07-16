#include <linux/export.h>
#include <linux/lsmpp_namespace.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>
#include <linux/proc_ns.h>
#include <linux/sched/task.h>
#include <linux/capability.h>
#include <linux/cred.h>

/**
 * Clone a new ns copying an original lsmpp namespace, setting refcount to 1
 * @old_ns: old lsmpp namespace to clone
 * @user_ns: user namespace that current task runs in
 * Return ERR_PTR(-ENOMEM) on error (failure to kmalloc), new ns otherwise
 */
static struct lsmpp_namespace *clone_lsmpp_ns(struct user_namespace *user_ns,
					  struct lsmpp_namespace *old_ns)
{
	struct lsmpp_namespace *ns;
	int err;
		
	if(old_ns->level > 32) {
		pr_err("Too much lsmpp ns\n");
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
	ns->ns.ops = &lsmppns_operations;
	get_lsmpp_ns(old_ns);	
	ns->level = old_ns->level + 1;
	ns->parent = old_ns;
	ns->user_ns = get_user_ns(user_ns);
	ns->state = 0; // Init
	memset(ns->progs, 0, LSMPP_HOOK_TYPE_SIZE * sizeof(ns->progs[0]));
	return ns;
}

/**
 * Copy task's lsmpp namespace, or clone it if flags
 * specifies CLONE_NEWLSMPP.  In latter case, events
 * in new lsmpp namespace will be measured against a
 * separate measurement policy and results will be
 * extended into a sparate measurement list
 *
 * @flags: flags used in the clone syscall
 * @user_ns: user namespace that current task runs in
 * @old_ns: old lsmpp namespace to clone
 */
struct lsmpp_namespace *copy_lsmpp_ns(unsigned long flags,
			       struct user_namespace *user_ns,
			       struct lsmpp_namespace *old_ns)
{
	struct lsmpp_namespace *new_ns;

	BUG_ON(!old_ns);
	get_lsmpp_ns(old_ns);

	if (!(flags & CLONE_NEWLSMPP))
		return old_ns;

	new_ns = clone_lsmpp_ns(user_ns, old_ns);
	put_lsmpp_ns(old_ns);

	return new_ns;
}

static void destroy_lsmpp_ns(struct lsmpp_namespace *ns)
{
	struct bpf_prog_array_item* item;
	int i;
	for(i=0; i<LSMPP_HOOK_TYPE_SIZE; ++i) { // We delete the progs stored in the NS
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

void free_lsmpp_ns(struct kref *kref)
{
	struct lsmpp_namespace *ns;
	struct lsmpp_namespace *parent;

	ns = container_of(kref, struct lsmpp_namespace, kref);
	parent = ns->parent;
	destroy_lsmpp_ns(ns);
	put_lsmpp_ns(parent);
}

static inline struct lsmpp_namespace *to_lsmpp_ns(struct ns_common *ns)
{
	return container_of(ns, struct lsmpp_namespace, ns);
}

static struct ns_common *lsmppns_get(struct task_struct *task)
{
	struct lsmpp_namespace *ns = NULL;
	struct nsproxy *nsproxy;

	task_lock(task);
	nsproxy = task->nsproxy;
	if (nsproxy) {
		ns = nsproxy->lsmpp_ns;
		get_lsmpp_ns(ns);
	}
	task_unlock(task);

	return ns ? &ns->ns : NULL;
}

static void lsmppns_put(struct ns_common *ns)
{
	put_lsmpp_ns(to_lsmpp_ns(ns));
}

static int lsmppns_install(struct nsproxy *nsproxy, struct ns_common *new)
{
	struct lsmpp_namespace *ns = to_lsmpp_ns(new);
	struct lsmpp_namespace *tmp = ns;

	if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN) ||
	    !ns_capable(current_user_ns(), CAP_SYS_ADMIN)) {
		do {
			if(tmp == nsproxy->lsmpp_ns)
				break; // Valid!
			if(tmp == &init_lsmpp_ns)
				return -EPERM;
			tmp = tmp->parent;
		} while(1);	
	}
	get_lsmpp_ns(ns);
	put_lsmpp_ns(nsproxy->lsmpp_ns);
	nsproxy->lsmpp_ns = ns;
	return 0;
}

const struct proc_ns_operations lsmppns_operations = {
	.name    = "lsmpp",
	.type    = CLONE_NEWLSMPP,
	.get     = lsmppns_get,
	.put     = lsmppns_put,
	.install = lsmppns_install,
};
