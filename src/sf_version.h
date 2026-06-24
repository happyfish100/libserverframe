/*
 * Copyright (c) 2026 YuQing <384681@qq.com>
 *
 * This program is free software: you can use, redistribute, and/or modify
 * it under the terms of the Lesser GNU General Public License, version 3
 * or later ("LGPL"), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the Lesser GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

//sf_version.h

#ifndef _SF_VERSION_H
#define _SF_VERSION_H

#include "fastcommon/common_define.h"

#define SF_MAJOR_VERSION   1
#define SF_MINOR_VERSION   2
#define SF_PATCH_VERSION  13

#define SF_VERSION_INT  FC_VERSION_TO_INT(SF_MAJOR_VERSION, \
        SF_MINOR_VERSION, SF_PATCH_VERSION)

#ifdef __cplusplus
extern "C" {
#endif

    int sf_version(Version *version);

#ifdef __cplusplus
}
#endif

#endif
