// SPDX-License-Identifier: GPL-2.0-only
/*
*
* SNAPPY Linux Security Module
*
* Author: Maxime Bélair <maxime.belair@orange.com>
*
* Copyright (C) 2020 - 2021 Orange
*/

#ifndef _LSMPP_FS_H
#define _LSMPP_FS_H

#include <linux/bpf.h>
#include <linux/fs.h>
#include <linux/types.h>

bool is_lsmpp_hook_file(struct file *f);

/*
 * The name of the directory created in securityfs
 *
 *  /sys/kernel/security/<dir_name>
 */

#define LSMPP_SFS_NAME "lsmpp"
#define LSMPP_POLICIES_DIR_NAME "policies"
#endif /* _LSMPP_FS_H */
