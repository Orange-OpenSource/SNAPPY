// SPDX-License-Identifier: GPL-2.0-only
/*
*
* SNAPPY Linux Security Module
*
* Author: Maxime Bélair <maxime.belair@orange.com>
*
* Copyright (C) 2020 - 2021 Orange
*/

SNAPPY_HOOK_INIT(BPRM_CHECK_SECURITY, bprm_check_security)
SNAPPY_HOOK_INIT(FILE_OPEN, file_open)
SNAPPY_HOOK_INIT(MMAP_FILE, mmap_file)
SNAPPY_HOOK_INIT(SOCKET_CONNECT, socket_connect)


// YAMA specific hooks
SNAPPY_HOOK_INIT(PTRACE_ACCESS_CHECK, ptrace_access_check)
SNAPPY_HOOK_INIT(PTRACE_TRACEME_HOOK, ptrace_traceme) // PTRACE_TRACEME is already defined as a const
SNAPPY_HOOK_INIT(TASK_PRCTL, task_prctl)
//SNAPPY_HOOK_INIT(TASK_FREE, task_free)

