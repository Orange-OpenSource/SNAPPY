// SPDX-License-Identifier: GPL-2.0-only
/*
*
* SNAPPY Linux Security Module
*
* Author: Maxime Bélair <maxime.belair@orange.com>
*
* Copyright (C) 2020 - 2021 Orange
*/


#ifndef SNAPPY_HOOK_H
#define SNAPPY_HOOK_H

enum LSM_HOOK_TYPE{
#define SNAPPY_HOOK_INIT(snappy, lsm) lsm,
#include "hooks.h"
#undef SNAPPY_HOOK_INIT
    LSM_HOOK_TYPE_SIZE,
};
enum SNAPPY_HOOK_TYPE{
#define SNAPPY_HOOK_INIT(snappy, lsm) snappy,
#include "hooks.h"
#undef SNAPPY_HOOK_INIT
    SNAPPY_HOOK_TYPE_SIZE,
};
#endif
