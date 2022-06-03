#ifndef __LINUX_SNAPPY_NS_H__
#define __LINUX_SNAPPY_NS_H__

#include <linux/kref.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/snappy.h>

#include <../security/snappy/include/snappy_hooks.h> // TODO FIX this
struct snappy_namespace {
	struct kref kref;
	struct user_namespace *user_ns;
	struct ns_common ns;
	struct snappy_namespace *parent;
	int level;
	int state;	
	struct bpf_prog_array __rcu *progs[SNAPPY_HOOK_TYPE_SIZE]; // array of ptrs
};

extern struct snappy_namespace init_snappy_ns;

#ifdef CONFIG_SNAPPY_NS
void free_snappy_ns(struct kref *kref);

static inline void get_snappy_ns(struct snappy_namespace *ns) {
	kref_get(&ns->kref);
}
	
static inline void put_snappy_ns(struct snappy_namespace *ns) {
	kref_put(&ns->kref, free_snappy_ns);
}
	
struct snappy_namespace *copy_snappy_ns(unsigned long flags,
                                   struct user_namespace *user_ns,
	                               struct snappy_namespace *old_ns);
	
#else
static inline void get_snappy_ns(struct snappy_namespace *ns)	{ return -EINVAL; }
	
static inline void put_snappy_ns(struct snappy_namespace *ns) { return -EINVAL; }
	
static inline struct snappy_namespace *copy_snappy_ns(unsigned long flags,
	                                             struct user_namespace *user_ns,
	                                             struct snappy_namespace *old_ns)
{
        if (flags & CLONE_SNAPPY)
                return ERR_PTR(-EINVAL);
        return old_ns;
}
#endif

#endif /* __LINUX_SNAPPY_NAMESPACE_H__*/ 
