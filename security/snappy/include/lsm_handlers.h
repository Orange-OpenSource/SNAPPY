// SPDX-License-Identifier: GPL-2.0-only
/*
*
* SNAPPY Linux Security Module
*
* Author: Maxime Bélair <maxime.belair@orange.com>
*
* Copyright (C) 2020 - 2021 Orange
*/

#ifndef LSM_HANDLERS_H
#define LSM_HANDLERS_H

//#include <linux/file.h>
//#include <linux/binfmts.h>

//struct security_hook_list* get_lsm_hook_from_type(enum snappy_hook_type t);
int snappy_bprm_check_security(struct linux_binprm* bprm, void** argv, void** envp);
int snappy_file_open(struct file* file);
int snappy_mmap_file(struct file* file, unsigned long reqprot,
    unsigned long prot, unsigned long flags);
int snappy_socket_connect(struct socket *sock, struct sockaddr *address,
	 int addrlen); 


int snappy_ptrace_access_check(struct task_struct *child, unsigned int mode);
int snappy_ptrace_traceme(struct task_struct *parent);
int snappy_task_prctl(int option, unsigned long arg2, unsigned long arg3,
               unsigned long arg4, unsigned long arg5);
int snappy_task_free(struct task_struct *task);

#endif
