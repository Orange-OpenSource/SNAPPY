#ifndef _LSMPP_H
#define _LSMPP_H
#include <linux/filter.h>
#include <linux/bpf.h>

#ifdef CONFIG_SECURITY_LSMPP
int lsmpp_prog_attach(const union bpf_attr* attr, struct bpf_prog* prog);
/*
struct lsmpp_bprm_ctx {
    struct linux_binprm *bprm;
};
struct lsmpp_file_ctx {
    struct file* file;
};
struct lsmpp_mmap_ctx {
    struct file* file;
    unsigned long reqprot;
    unsigned long prot;
    unsigned long flags;
};
*/
extern const struct bpf_func_proto lsmpp_dynamic_call_proto;
/*struct lsmpp_ctx {
	int state; // The current state of the namespace
    union {
        struct lsmpp_bprm_ctx bprm_ctx;
        struct lsmpp_file_ctx file_ctx;
        struct lsmpp_mmap_ctx mmap_ctx;
        // TODO more stuff to add!
    };
};*/
#else
static inline int lsmpp_prog_attach(const union bpf_attr* attr, struct bpf_prog* prog) {
    return -EINVAL;
}
#endif

#endif
