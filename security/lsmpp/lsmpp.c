
#include <linux/lsm_hooks.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/binfmts.h>
#include <linux/highmem.h>
#include <linux/lsmpp.h>
#include <linux/mm.h>
#include <linux/pid_namespace.h>

//#include "lsmpp_init.h"
#include "lsmpp.h"
#include "lsm_handlers.h"
struct bpf_helper_array helper_array;



static bool is_lsm_hook_init[LSM_HOOK_TYPE_SIZE];

bool lsm_hook_is_init(enum LSMPP_HOOK_TYPE type)  {
        return !!is_lsm_hook_init[type];
}
bool lsm_init_hook(enum LSMPP_HOOK_TYPE type) {

	struct security_hook_list* hook = kmalloc(sizeof(struct security_hook_list), GFP_KERNEL);
    switch(type) {
    #define LSMPP_HOOK_INIT(lsmpp, lsm)					\
        case lsmpp:										\
            hook[0].head = &security_hook_heads. lsm;	\
            hook[0].hook. lsm = &lsmpp_ ## lsm;			\
            break;

    #include "hooks.h"
    #undef LSMPP_HOOK_INIT
    default:
        pr_err("Trying to access inexistant hook n°%d", type);
    	return false;
	}
    is_lsm_hook_init[type]=true;    // TODO: Add a synchronization primitive.
    security_late_add_hooks(hook, 1, "lsmpp");
    return true;
}

/* A new bpf call is attached via bpf() syscall */
int lsmpp_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog) {
    struct bpf_prog_array *old_array;
    struct bpf_prog_array *new_array;
    struct lsmpp_hook *h;
    
	int ret = 0;

    struct lsmpp_helper_ctx* new_entry;

    pid_t pid = task_pid_nr(current);

    //pr_debug("BPF LOADER: Called from pid=%d\n", pid);
    //pr_debug("BPF LOADER: pid_gid from pid_namespace = %d\n", current->nsproxy->pid_ns_for_children->pid_gid.val);
    //pr_debug("Todel: Kern fd = %d\n" ,attr->target_fd);

    h = get_hook_from_fd(attr->target_fd);
    if (IS_ERR(h))
        return PTR_ERR(h);

    mutex_lock(&h->mutex);

    new_entry = kmalloc(sizeof(struct lsmpp_helper_ctx), GFP_KERNEL);
    new_entry->nsproxy = current->nsproxy;
    list_add_tail(&new_entry->list, &h->helper_ctx_list);

    old_array = rcu_dereference_protected(h->progs,
                          lockdep_is_held(&h->mutex));
    ret = bpf_prog_array_copy(old_array, /*old_prog*/ NULL, prog, &new_array);
    /* Note: we keep all the programs, even the old one. */
    if (ret < 0) {
        ret = -ENOMEM;
        goto unlock;
    }
    rcu_assign_pointer(h->progs, new_array);
    bpf_prog_array_free(old_array);

unlock:
    mutex_unlock(&h->mutex);
    return ret;
}
int lsmpp_load_open (struct inode * i, struct file * f) {
    struct mmap_info* info = kmalloc(sizeof(struct mmap_info), GFP_KERNEL);
	info->data = NULL; 
    f->private_data = info;
    return 0;
}
int lsmpp_load_release(struct inode* i, struct file* f) {
    struct mmap_info* info = f->private_data;
    vfree(info->data);
    kfree(info);
    f->private_data = NULL;
    return 0;
}
int save_code(struct mmap_info* info, int size) {
    // TODO Check rights to check on a lsm.
    struct bpf_helper h;
    if(!lsm_hook_is_init(info->hook_type)) {
		pr_debug("Initializing new lsm hook (id=%d)\n", info->hook_type);

		if(!lsmpp_init_hook(&lsmpp_hook_array[info->hook_type]) && !lsm_init_hook(info->hook_type)) {
        	pr_err("Error initializing hook id=%d\n", info->hook_type);
			return -1;
		}

    }
    // TODO: parse metadata there
    // -> Namespaces ids <-
    // -> Process id <-
    // -> 

    h = new_bpf_helper(info->data, size, info->offset);
    add_bpf_helper(&helper_array, h);
    debug_print_helpers(helper_array);
    return 0;
}
static bool parse_msg(struct mmap_info* info, const char __user* msg, size_t sz, loff_t* offset) {
    uint8_t header_buf[HEADER_SZ];
 
    pr_debug("Write\n");

	if(sz > HELPER_MAX_SIZE) {
		pr_err("Trying to load too big helper (sz=%ld/%dB)\n", sz, HELPER_MAX_SIZE );
		return false;
	}
	if(helper_array.number + 1 >= helper_array.maxnumber) {
		pr_err("Too much bpf helpers (nb=%dB)\n", helper_array.number + 1);
		return false;
	}
	if(helper_array.size + sz > helper_array.maxsize) {
		pr_err("Bpf helpers above maxsize (sz=%lld/%lldB)\n", helper_array.size + sz, helper_array.size);
		return -false;
	}
    if(copy_from_user(header_buf, msg, HEADER_SZ)) {
        pr_err("Fault writing \n");
                return false;
    }

    info->proto 	= *((uint8_t *)(header_buf + 0));
    info->offset    = *((uint32_t*)(header_buf + 1));
    info->hook_type = *((uint8_t *)(header_buf + 9));	
	info->data 		= __vmalloc(sz - HEADER_SZ, GFP_KERNEL, PAGE_KERNEL_EXEC);

    pr_debug("OK, copying buffer\n");
    if (copy_from_user(((void*) info->data), msg + HEADER_SZ , sz - HEADER_SZ)) {
        pr_err("Fault writing\n");
                return false;
    }
	pr_debug("Done\n");
    return true;
}


ssize_t lsmpp_load_write(struct file* f, const char __user* msg, size_t sz, loff_t* offset) {
    // TODO: handle fracionated msg.
    struct mmap_info* info = f->private_data;
    
	pr_debug("In write : offset=%lld\n", *offset);

    if(!parse_msg(info, msg, sz, offset)) {
		pr_debug("invalid msg\n");
		return -EINVAL;	// Invalid message
	}
    pr_debug("Msg parsed, proto=%d\n", info->proto);
	switch(info->proto) {
    case STORE_BUFFER:
        save_code(info, sz - HEADER_SZ);
        break;
	default:
		pr_err("Trying to sent wrong packet\n");
		return -EINVAL;
    }
        return sz;

}
static const struct bpf_func_proto *lsmpp_prog_func_proto(enum bpf_func_id func_id,
                             const struct bpf_prog *prog) {
    switch (func_id) {
    case BPF_FUNC_lsmpp_dynamic_call:
        return &lsmpp_dynamic_call_proto;
    default:
        return NULL;
    }
}
static bool lsmpp_prog_is_valid_access(int off, int size,
                      enum bpf_access_type type,
                      const struct bpf_prog *prog,
                      struct bpf_insn_access_aux *info)
{
    /*
     * LSMPP is conservative about any direct access in eBPF to
     * prevent the users from depending on the internals of the kernel and
     * aims at providing a rich eco-system of safe eBPF helpers as an API
     * for accessing relevant information from the context.
     */
    return false;
}

const struct bpf_verifier_ops lsmpp_verifier_ops = {
    .get_func_proto = lsmpp_prog_func_proto,
    .is_valid_access = lsmpp_prog_is_valid_access,
};
const struct bpf_prog_ops lsmpp_prog_ops = {
};
/* 
static inline bool bpf_is_call_to_func(struct bpf_insn *insn,
				       void *func_addr)
{
	u8 opcode = BPF_OP(insn->code);

	if (opcode != BPF_CALL)
		return false;

	if (insn->src_reg == BPF_PSEUDO_CALL)
		return false;

	*
	 * The BPF verifier updates the value of insn->imm from the
	 * enum bpf_func_id to the offset of the address of helper
	 * from the __bpf_call_base.
	 *
	return __bpf_call_base + insn->imm == func_addr;
}
*/

//struct lsmpp_hook* lsmpp_hook_array;

struct lsmpp_hook lsmpp_hook_array[] = {
	#define LSMPP_HOOK_INIT(TYPE, NAME) \
		[TYPE] = { \
			.h_type = TYPE, \
			.name = #NAME, \
			.helper_ctx_list = LIST_HEAD_INIT(lsmpp_hook_array[TYPE].helper_ctx_list), \
		},
	#include "hooks.h"
	#undef LSMPP_HOOK_INIT
};

#define lsmpp_bpf_prog_array_is_empty(type) (bpf_prog_array_is_empty(lsmpp_hook_array[type].progs))
/*
int lsmpp_process_execution(struct linux_binprm *bprm)
{
	int ret;
	struct lsmpp_ctx ctx;
	if(lsmpp_bpf_prog_array_is_empty(BPRM_CHECK_SECURITY)) {
		// pr_debug("No bpf program loaded yet.\n");
		return 0;
	}

	ctx.bprm_ctx = (struct lsmpp_bprm_ctx) {
		.bprm = bprm,
	};
	
//todel	printk(KERN_INFO "Begin lsmpp_process_execution");

	/ *printk(KERN_INFO "BPRM=%p, arg pages=%s, num args = %zu max args = %zu",
			ctx.bprm_ctx.bprm,
			ctx.bprm_ctx.arg_pages,
			ctx.bprm_ctx.num_arg_pages,
			ctx.bprm_ctx.max_arg_offset
	);* /
	if (READ_ONCE(need_arg_pages)) {
		printk(KERN_INFO "Need arg pages");
		ret = pin_arg_pages(&ctx.bprm_ctx);
		if (ret < 0) {
			printk(KERN_INFO "Ret < 0");
			goto out_arg_pages;
		}
	}
	lsmpp_get_ns(BPRM_CHECK_SECURITY, bprm);
	ret = lsmpp_run_progs(PROCESS_EXECUTION, &ctx);
	kfree(ctx.bprm_ctx.arg_pages);

out_arg_pages:
	return ret;
}
*/

/*
static struct security_hook_list lsmpp_hooks[] __lsm_ro_after_init = {
	#define LSMPP_HOOK_INIT(T, N, HOOK, IMPL, CB) LSM_HOOK_INIT(HOOK, IMPL),
	#include "hooks.h"
	#undef LSMPP_HOOK_INIT
};
*/

static int __init lsmpp_init(void)
{
	//lsmpp_hook_array = kmalloc(LSM_HOOK_TYPE_SIZE * sizeof(struct lsmpp_hook), GFP_KERNEL); 
	helper_array = new_bpf_helper_array();
	security_add_hooks(NULL, 0, "lsmpp"); // Hooks are added dynamically, we should start from 0 hook
	pr_info("LSM++ is initialized\n");	
	return 0;
}

DEFINE_LSM(lsmpp) = {
	.name = "lsmpp",
	.init = lsmpp_init,
};
