#ifndef LSM_HANDLERS
#define LSM_HANDLERS

//#include <linux/file.h>
//#include <linux/binfmts.h>

//struct security_hook_list* get_lsm_hook_from_type(enum lsmpp_hook_type t);
int lsmpp_bprm_check_security(struct linux_binprm* bprm);
int lsmpp_file_open(struct file* file);
int lsmpp_mmap_file(struct file* file, unsigned long reqprot,
    unsigned long prot, unsigned long flags);

#endif
