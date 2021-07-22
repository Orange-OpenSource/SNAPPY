// SPDX-License-Identifier: GPL-2.0-only
/*
*
* SNAPPY Linux Security Module
*
* Author: Maxime Bélair <maxime.belair@orange.com>
*
* Copyright (C) 2020 - 2021 Orange
*/

#ifndef LSMPP_H
#define LSMPP_H

#include <linux/module.h>
#include <linux/lsmpp.h>
#include <linux/lsmpp_namespace.h>

#include "lsmpp_hooks.h"

#undef pr_fmt
#define pr_fmt(fmt) "LSM++: " fmt



// todo: remove this redondent type.
struct mmap_info {
    char *data;
	uint32_t nb_helpers;
	uint32_t* entrypoints;
	uint32_t got_offset, got_size;    
    char proto;
    enum LSMPP_HOOK_TYPE hook_type;
    void** args;
	uint8_t* name;
};

enum proto {
	STORE_BUFFER,
};

//// LSMPP ////

struct bpf_helper {
	void* helper; // TODO: swap to a more explicit type than void*.
	uint32_t nb_helpers;
	uint32_t* entrypoints;
	uint32_t code_size;
	unsigned char* hash;
	char* name;
};

struct bpf_helper_array {
	struct bpf_helper* helpers; // It seems that there will be few/no removals thus array might be more space-effient than linked-list.
	uint32_t number, maxnumber;
	uint64_t size, maxsize;
};
// TODO: filp or global variable??
extern struct bpf_helper_array helper_array;

/*struct lsmpp_helper_ctx {
	int pid;
	struct nsproxy* nsproxy;
	struct pid_namespace* pidns;
	struct list_head list;
};
*/
struct lsmpp_hook {
    /*
     * The name of the security hook, a file with this name will be created
     * in the securityfs.
     */
    const char *name;
    /*
     * The type of the LSM hook, the LSM uses this to index the list of the
     * hooks to run the eBPF programs that may have been attached.
     */
    enum LSMPP_HOOK_TYPE h_type;
    /*
     * The dentry of the file created in securityfs.
     */
    struct dentry *h_dentry;
    /*
     * The mutex must be held when updating the progs attached to the hook.
     */
    struct mutex mutex;
    /*
     * The eBPF programs that are attached to this hook.
     */
//    struct bpf_prog_array __rcu * progs;

    /*
     * The Namespace environment for bpf progs. Required to decide whether the bpf prog has a visibility
     * over the object thus have  to be runned. progs.items[i] is associated to nsproxy[i]
     * FIXME: This nsproxy would be better if directly in the bpf_helper_array_item struct. But sinsce a lot
     * of functions are reused it would require to reimplement or modify all the associated methods which
     * can be problematic.
     * This solution is not really satisfactory either because it complexifies accesses and requieres to
     * synchronize theses structs for coherency.
     * ==> Needs to find a better solution.
     */
//    struct list_head helper_ctx_list;
};

extern struct lsmpp_hook lsmpp_hook_array[];

//// INIT ////
int lsmpp_init_hook(struct lsmpp_hook *h); 
bool lsm_init_hook(enum LSMPP_HOOK_TYPE type);
bool lsm_hook_is_init(enum LSMPP_HOOK_TYPE type);
//// END INIT ////



int lsmpp_load_open (struct inode * i, struct file * f);
int lsmpp_load_release(struct inode* i, struct file* f);
ssize_t lsmpp_load_write(struct file* f, const char __user* msg, size_t len, loff_t* offset); 

ssize_t lsmpp_get_helpers(struct file * _, char __user* buf, size_t sz, loff_t* offset);

int lsmpp_run_progs(enum LSMPP_HOOK_TYPE t, struct lsmpp_ctx *ctx) ;

/* Implemented in libdb.c */
/*#define lsmpp_for_each_hook(hook) \
	for ((hook) = &lsmpp_hook_array[0]; \
		(hook) < &lsmpp_hooks_array[LSMPP_HOOK_TYPE_SIZE]; \
		(hook)++)
*/
#define INITIAL_BPF_ARRAY_NUMBER 256
#define HELPER_MAX_SIZE (16*1024*1024)		// 16MO
#define BPF_ARRAY_MAX_SIZE (1024*1024*1024) // Max size is 1GO
#define increase_array_strategy(oldnb) (2*oldnb)
/*
inline void lsmpp_get_ns(enum LSMPP_HOOK_TYPE hook_type, struct linux_binprm* bprm);
*/
inline struct bpf_code_array new_bpf_code_array(void); 
int add_bpf_helper(struct bpf_helper_array* arr, struct bpf_helper code);
int del_bpf_helper(struct bpf_helper_array* arr, int idx);
void __init init_bpf_helpers(void);
struct bpf_helper new_bpf_helper(struct mmap_info* info, int code_size);
void debug_print_helpers(struct bpf_helper_array arr);

/*
// Implemented in libexec.c

extern int sysctl_unprivileged_bpf_disabled;
int save_code(struct mmap_info* info, int size);
int exec_lib(int id, void** args);
int direct_exec(struct mmap_info* info, void** args);
int save_path(struct mmap_info* info);
int bpf_load_exec(struct mmap_info* info);

// End (libexec.c)

*/
struct lsmpp_hook *get_hook_from_fd(int fd);


int save_code(struct mmap_info* info, int size);
#ifdef CONFIG_RANDOMIZE_BASE
inline unsigned long int get_kaslr_offset(void);
#endif
#endif
