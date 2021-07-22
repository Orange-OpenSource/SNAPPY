// SPDX-License-Identifier: GPL-2.0-only
/*
*
* SNAPPY Linux Security Module
*
* Author: Maxime Bélair <maxime.belair@orange.com>
*
* Copyright (C) 2020 - 2021 Orange
*/


#ifndef LSMPP_HOOK_H
#define LSMPP_HOOK_H

enum LSM_HOOK_TYPE{
#define LSMPP_HOOK_INIT(lsmpp, lsm) lsm,
#include "hooks.h"
#undef LSMPP_HOOK_INIT
    LSM_HOOK_TYPE_SIZE,
};
enum LSMPP_HOOK_TYPE{
#define LSMPP_HOOK_INIT(lsmpp, lsm) lsmpp,
#include "hooks.h"
#undef LSMPP_HOOK_INIT
    LSMPP_HOOK_TYPE_SIZE,
};
#endif
