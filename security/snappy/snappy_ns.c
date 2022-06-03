// SPDX-License-Identifier: GPL-2.0-only
/*
*
* SNAPPY Linux Security Module
*
* Author: Maxime Bélair <maxime.belair@orange.com>
*
* Copyright (C) 2020 - 2021 Orange
*/

#include <linux/export.h>
#include <linux/user_namespace.h>
#include <linux/proc_ns.h>
#include <linux/snappy_namespace.h>

struct snappy_namespace init_snappy_ns = {
	.kref = KREF_INIT(2),
	.user_ns = &init_user_ns,
	.ns.inum = PROC_SNAPPY_INIT_INO,
#ifdef CONFIG_SNAPPY_NS
	.ns.ops = &snappyns_operations,
#endif
	.parent = NULL,
	.level = 0,
	.state = 0,
};
EXPORT_SYMBOL(init_snappy_ns);
