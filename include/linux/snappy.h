#ifndef _SNAPPY_H
#define _SNAPPY_H
#include <linux/filter.h>
#include <linux/bpf.h>

#ifdef CONFIG_SECURITY_SNAPPY
int snappy_prog_attach(const union bpf_attr* attr, struct bpf_prog* prog);
/*
struct snappy_bprm_ctx {
    struct linux_binprm *bprm;
};
struct snappy_file_ctx {
    struct file* file;
};
struct snappy_mmap_ctx {
    struct file* file;
    unsigned long reqprot;
    unsigned long prot;
    unsigned long flags;
};
*/
extern const struct bpf_func_proto snappy_dynamic_call_proto;
/*struct snappy_ctx {
	int state; // The current state of the namespace
    union {
        struct snappy_bprm_ctx bprm_ctx;
        struct snappy_file_ctx file_ctx;
        struct snappy_mmap_ctx mmap_ctx;
        // TODO more stuff to add!
    };
};*/
#else
static inline int snappy_prog_attach(const union bpf_attr* attr, struct bpf_prog* prog) {
    return -EINVAL;
}
#endif

#endif
