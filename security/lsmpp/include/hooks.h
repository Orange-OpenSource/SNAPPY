/*
* Software Name : SNAPPY
* Version: 0.0.1
* SPDX-FileCopyrightText: Copyright (c) 2021 Orange
*
* This software is confidential and proprietary information of Orange.
* You shall not disclose such Confidential Information and shall not copy, use or distribute it
* in whole or in part without the prior written consent of Orange
*
* Author: Maxime Bélair
*/
LSMPP_HOOK_INIT(BPRM_CHECK_SECURITY, bprm_check_security)
LSMPP_HOOK_INIT(FILE_OPEN, file_open)
LSMPP_HOOK_INIT(MMAP_FILE, mmap_file)
LSMPP_HOOK_INIT(SOCKET_CONNECT, socket_connect)


// YAMA specific hooks
LSMPP_HOOK_INIT(PTRACE_ACCESS_CHECK, ptrace_access_check)
LSMPP_HOOK_INIT(PTRACE_TRACEME_HOOK, ptrace_traceme) // PTRACE_TRACEME is already defined as a const
LSMPP_HOOK_INIT(TASK_PRCTL, task_prctl)
//LSMPP_HOOK_INIT(TASK_FREE, task_free)

