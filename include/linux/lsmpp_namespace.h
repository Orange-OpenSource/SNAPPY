#ifndef __LINUX_LSMPP_NS_H__
#define __LINUX_LSMPP_NS_H__

#include <linux/kref.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/lsmpp.h>

#include <../security/lsmpp/include/lsmpp_hooks.h> // TODO FIX this
struct lsmpp_namespace {
	struct kref kref;
	struct user_namespace *user_ns;
	struct ns_common ns;
	struct lsmpp_namespace *parent;
	int level;
	int state;	
	struct bpf_prog_array __rcu *progs[LSMPP_HOOK_TYPE_SIZE]; // array of ptrs
};

extern struct lsmpp_namespace init_lsmpp_ns;

#ifdef CONFIG_LSMPP_NS
void free_lsmpp_ns(struct kref *kref);

static inline void get_lsmpp_ns(struct lsmpp_namespace *ns) {
	kref_get(&ns->kref);
}
	
static inline void put_lsmpp_ns(struct lsmpp_namespace *ns) {
	kref_put(&ns->kref, free_lsmpp_ns);
}
	
struct lsmpp_namespace *copy_lsmpp_ns(unsigned long flags,
                                   struct user_namespace *user_ns,
	                               struct lsmpp_namespace *old_ns);
	
#else
static inline void get_lsmpp_ns(struct lsmpp_namespace *ns)	{ return -EINVAL; }
	
static inline void put_lsmpp_ns(struct lsmpp_namespace *ns) { return -EINVAL; }
	
static inline struct lsmpp_namespace *copy_lsmpp_ns(unsigned long flags,
	                                             struct user_namespace *user_ns,
	                                             struct lsmpp_namespace *old_ns)
{
        if (flags & CLONE_LSMPP)
                return ERR_PTR(-EINVAL);
        return old_ns;
}
#endif

#endif /* __LINUX_LSMPP_NAMESPACE_H__*/ 
