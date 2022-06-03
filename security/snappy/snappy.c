// SPDX-License-Identifier: GPL-2.0-only
/*
*
* SNAPPY Linux Security Module
*
* Author: Maxime Bélair <maxime.belair@orange.com>
*
* Copyright (C) 2020 - 2021 Orange
*/

#include <linux/lsm_hooks.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/binfmts.h>
#include <linux/highmem.h>
#include <linux/snappy.h>
#include <linux/mm.h>
#include <linux/pid_namespace.h>
#include <linux/device.h>
#include <linux/ctype.h>

//#include "snappy_init.h"
#include "snappy.h"
#include "lsm_handlers.h"
struct bpf_helper_array helper_array;

static bool is_lsm_hook_init[LSM_HOOK_TYPE_SIZE];

bool lsm_hook_is_init(enum SNAPPY_HOOK_TYPE type)  {
        return !!is_lsm_hook_init[type];
}
bool lsm_init_hook(enum SNAPPY_HOOK_TYPE type) {

	struct security_hook_list* hook = kmalloc(sizeof(struct security_hook_list), GFP_KERNEL);
    switch(type) {
    #define SNAPPY_HOOK_INIT(snappy, lsm)					\
        case snappy:										\
            hook[0].head = &security_hook_heads. lsm;	\
            hook[0].hook. lsm = &snappy_ ## lsm;			\
            break;

    #include "hooks.h"
    #undef SNAPPY_HOOK_INIT
    default:
        pr_err("Trying to access inexistant hook n°%d", type);
    	return false;
	}
    is_lsm_hook_init[type]=true;    // TODO: Add a synchronization primitive.
    security_late_add_hooks(hook, 1, "snappy");
    return true;
}

/* A new bpf call is attached via bpf() syscall */
int snappy_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog) {
    struct bpf_prog_array *old_array;
    struct bpf_prog_array *new_array;
    struct snappy_hook *h;
    
	int ret = 0;

//    struct snappy_helper_ctx* new_entry;

    //pid_t pid = task_pid_nr(current);

    //pr_debug("BPF LOADER: Called from pid=%d\n", pid);
    //pr_debug("BPF LOADER: pid_gid from pid_namespace = %d\n", current->nsproxy->pid_ns_for_children->pid_gid.val);
    //pr_debug("Todel: Kern fd = %d\n" ,attr->target_fd);

    h = get_hook_from_fd(attr->target_fd);
    if (IS_ERR(h))
        return PTR_ERR(h);

    mutex_lock(&h->mutex);

//    new_entry = kmalloc(sizeof(struct snappy_helper_ctx), GFP_KERNEL);
//    new_entry->nsproxy = current->nsproxy;
//    new_entry->pid = pid;
//	new_entry->pidns = task_active_pid_ns(current);
//	pr_debug("Attaching pid=%d, pidns=%p", new_entry->pid, new_entry->pidns);
//	list_add_tail(&new_entry->list, &h->helper_ctx_list);

	old_array = rcu_dereference_protected(current->nsproxy->snappy_ns->progs[h->h_type],
                          lockdep_is_held(&h->mutex));
	if(!old_array) {
    	old_array = bpf_prog_array_alloc(0, GFP_KERNEL);
    	if (!old_array) {
        	ret = -ENOMEM;
	        goto unlock;
    	}
	    RCU_INIT_POINTER(current->nsproxy->snappy_ns->progs[h->h_type], NULL);
	}
    ret = bpf_prog_array_copy(old_array, /*old_prog*/ NULL, prog, 0, &new_array);
    /* Note: we keep all the programs, even the old one. */
    if (ret < 0) {
        ret = -ENOMEM;
        goto unlock;
    }
    rcu_assign_pointer(current->nsproxy->snappy_ns->progs[h->h_type], new_array);
    bpf_prog_array_free(old_array);

unlock:
    mutex_unlock(&h->mutex);
    return ret;
}
int snappy_load_open (struct inode * i, struct file * f) {
    struct mmap_info* info = kmalloc(sizeof(struct mmap_info), GFP_KERNEL);
	info->data = NULL; 
    f->private_data = info;
    return 0;
}
int snappy_load_release(struct inode* i, struct file* f) {
    struct mmap_info* info = f->private_data;
    vfree(info->data);
    kfree(info);
    f->private_data = NULL;
    return 0;
}


// todo check sizes
ssize_t snappy_get_helpers(struct file * _, char __user* buf, size_t sz, loff_t* offset) {  
	int err = 0,  i, copysz, copied=0;
	struct bpf_helper h;
	if(offset<0 || sz<=0 || *offset+sz<0)
		return -EINVAL;

	for(i=*offset; i<helper_array.number; ++i) {
		h = helper_array.helpers[i];
		copysz = strlen(h.name) +1;
		if(copied + copysz + 32 > sz) { // If the buffer is full we stop there.
			return copied;
		}
		err = copy_to_user(buf+copied, h.name, copysz);
		if(err) {
			pr_err("Failed to send helper data");
			return -EINVAL;
		}
		err = copy_to_user(buf+copied+copysz, h.hash, 32); // 256 bits.
		if(err) {
			pr_err("Failed to send helper hash");
			return -EINVAL;
		}
		copied += copysz + 32;
		++*offset;
	}
	return copied;
}

int save_code(struct mmap_info* info, int code_size) {
    // TODO Check rights to check on a lsm.
    struct bpf_helper h;
    if(!lsm_hook_is_init(info->hook_type)) {
		pr_debug("Initializing new lsm hook (id=%d)\n", info->hook_type);
		if(!snappy_init_hook(&snappy_hook_array[info->hook_type]) && !lsm_init_hook(info->hook_type)) {
        	pr_err("Error initializing hook id=%d\n", info->hook_type);
			return -1;
		}	
		printk(KERN_INFO "LSM hook Inited\n");
    }
    // TODO: parse metadata there
    // -> Namespaces ids <-
    // -> Process id <-
    // -> 
    h = new_bpf_helper(info, code_size);
    pr_info("new helper created\n");
	add_bpf_helper(&helper_array, h);
	pr_info("helper added\n");
    debug_print_helpers(helper_array);
    return 0;
}

// FIXME: add the needed verification to sanitize this **USERSPACE** input
static int parse_msg(struct mmap_info* info, const char __user* msg, size_t sz, loff_t* offset) {
    #define header_sz 25
	uint8_t header_buf[header_sz];
	int len;
	int i;
	int code_size;

    pr_debug("Write\n");

	if(sz > HELPER_MAX_SIZE) {
		pr_err("Trying to load too big helper (sz=%ld/%dB)\n", sz, HELPER_MAX_SIZE );
		return -EINVAL;
	}
	if(helper_array.number + 1 >= helper_array.maxnumber) {
		pr_err("Too much bpf helpers (nb=%d)\n", helper_array.number + 1);
		return -EINVAL;
	}
	if(helper_array.size + sz > helper_array.maxsize) {
		pr_err("Bpf helpers above maxsize (sz=%lld/%lldB)\n", helper_array.size + sz, helper_array.size);
		return -EINVAL;
	}
	if(copy_from_user(header_buf, msg, header_sz)) {
		pr_err("Fault writing \n");
        	return -EINVAL;
	}

	info->proto 	 = *((uint8_t *)(header_buf + 0));
	info->hook_type  = *((uint32_t*)(header_buf + 1));
	info->nb_helpers = *((uint32_t*)(header_buf + 5));
	info->got_offset= *((uint32_t *)(header_buf + 9));
	info->got_size = *((uint32_t*)(header_buf + 13));
	
	info->name = kmalloc(33, GFP_KERNEL);
	len = strncpy_from_user(info->name, (const uint8_t __user *)*((unsigned long **)(header_buf+17)), 33);
	if(len <= 0 || len >= 32) {
		pr_err("Fault reading names\n");
		kfree(info->name);
		return -EINVAL;
	}
	for(i=0; info->name[i]; ++i)
		if(!isalnum(info->name[i]) && info->name[i] != '_' ) {
			pr_err("Fault reading names\n");
			return -EINVAL;
		} 
	
	info->entrypoints = kmalloc(info->nb_helpers* sizeof(uint32_t), GFP_KERNEL);

	if(copy_from_user((uint8_t*)info->entrypoints, msg + header_sz, info->nb_helpers * sizeof(uint32_t))) {
		pr_err("Fault writing\n");
		return -EINVAL;
	}
	code_size = sz - header_sz - info->nb_helpers * sizeof(uint32_t);
	info->data 		= __vmalloc_node_range(code_size, 1, VMALLOC_START, VMALLOC_END,
			GFP_KERNEL, PAGE_KERNEL_EXEC, VM_FLUSH_RESET_PERMS,
			NUMA_NO_NODE, __builtin_return_address(0));

    pr_debug("OK code offset=%x, got offset=%x, copying buffer\n", info->entrypoints[0], info->got_offset);
    if (copy_from_user(((void*) info->data), msg + header_sz + info->nb_helpers * sizeof(uint32_t), code_size)) {
        pr_err("Fault writing\n");
		return -EINVAL;
    }
	pr_debug("Done\n");
    return code_size;
	#undef header_sz
}


ssize_t snappy_load_write(struct file* f, const char __user* msg, size_t sz, loff_t* offset) {
    // TODO: handle fracionated msg.
    struct mmap_info* info = f->private_data;
 	int code_sz;   
	pr_debug("In write : offset=%lld\n", *offset);
	code_sz = parse_msg(info, msg, sz, offset);
    if(code_sz <= 0) {
		pr_debug("invalid msg\n");
		return -EINVAL;	// Invalid message
	}
    pr_debug("Msg parsed, proto=%d\n", info->proto);
	switch(info->proto) {
    case STORE_BUFFER:
        save_code(info, code_sz);
        break;
	default:
		pr_err("Trying to sent wrong packet\n");
		return -EINVAL;
    }
        return sz;

}
static const struct bpf_func_proto *snappy_prog_func_proto(enum bpf_func_id func_id,
                             const struct bpf_prog *prog) {
    switch (func_id) {
    case BPF_FUNC_snappy_dynamic_call:
        return &snappy_dynamic_call_proto;
    default:
        return NULL;
    }
}
static bool snappy_prog_is_valid_access(int off, int size,
                      enum bpf_access_type type,
                      const struct bpf_prog *prog,
                      struct bpf_insn_access_aux *info)
{
    /*
     * SNAPPY is conservative about any direct access in eBPF to
     * prevent the users from depending on the internals of the kernel and
     * aims at providing a rich eco-system of safe eBPF helpers as an API
     * for accessing relevant information from the context.
     */
    return false;
}

const struct bpf_verifier_ops snappy_verifier_ops = {
    .get_func_proto = snappy_prog_func_proto,
    .is_valid_access = snappy_prog_is_valid_access,
};
const struct bpf_prog_ops snappy_prog_ops = {
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

//struct snappy_hook* snappy_hook_array;

struct snappy_hook snappy_hook_array[] = {
	#define SNAPPY_HOOK_INIT(TYPE, NAME) \
		[TYPE] = { \
			.h_type = TYPE, \
			.name = #TYPE \
			/*.helper_ctx_list = LIST_HEAD_INIT(snappy_hook_array[TYPE].helper_ctx_list),*/ \
		},
	#include "hooks.h"
	#undef SNAPPY_HOOK_INIT
};

#define snappy_bpf_prog_array_is_empty(type) (bpf_prog_array_is_empty(snappy_hook_array[type].progs))
/*
int snappy_process_execution(struct linux_binprm *bprm)
{
	int ret;
	struct snappy_ctx ctx;
	if(snappy_bpf_prog_array_is_empty(BPRM_CHECK_SECURITY)) {
		// pr_debug("No bpf program loaded yet.\n");
		return 0;
	}

	ctx.bprm_ctx = (struct snappy_bprm_ctx) {
		.bprm = bprm,
	};
	
//todel	printk(KERN_INFO "Begin snappy_process_execution");

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
	snappy_get_ns(BPRM_CHECK_SECURITY, bprm);
	ret = snappy_run_progs(PROCESS_EXECUTION, &ctx);
	kfree(ctx.bprm_ctx.arg_pages);

out_arg_pages:
	return ret;
}
*/

/*
static struct security_hook_list snappy_hooks[] __lsm_ro_after_init = {
	#define SNAPPY_HOOK_INIT(T, N, HOOK, IMPL, CB) LSM_HOOK_INIT(HOOK, IMPL),
	#include "hooks.h"
	#undef SNAPPY_HOOK_INIT
};
*/
#ifdef CONFIG_RANDOMIZE_BASE
unsigned long static int kaslr_offset = 0;

inline unsigned long int get_kaslr_offset() {
	return kaslr_offset;
}
#endif
static int __init snappy_init(void)
{
	//snappy_hook_array = kmalloc(LSM_HOOK_TYPE_SIZE * sizeof(struct snappy_hook), GFP_KERNEL);
	//helper_array = init_bpf_helpers();
	security_add_hooks(NULL, 0, "snappy"); // Hooks are added dynamically, we should start from 0 hook
	#ifdef CONFIG_RANDOMIZE_BASE
	/*To determine the kaslr_offset, we compare the memory emplacement of an address compared to
	 its location without kaslr. TODO: is there a cleaner way to do this? */
	kaslr_offset = kallsyms_lookup_name("_text") - 0xffffffff81000000;
	pr_info("kaslr_offset=%lx", kaslr_offset);
	#endif
	pr_info("Snappy is initialized\n");	
	return 0;
}

DEFINE_LSM(snappy) = {
	.name = "snappy",
	.init = snappy_init,
};
