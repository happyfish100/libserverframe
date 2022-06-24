/*
 * Copyright (c) 2020 YuQing <384681@qq.com>
 *
 * This program is free software: you can use, redistribute, and/or modify
 * it under the terms of the GNU Affero General Public License, version 3
 * or later ("AGPL"), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */


#ifndef _IDEMPOTENCY_COMMON_TYPES_H
#define _IDEMPOTENCY_COMMON_TYPES_H

#include "fastcommon/common_define.h"

#define SF_IDEMPOTENCY_CHANNEL_ID_BITS    16
#define SF_IDEMPOTENCY_REQUEST_ID_BITS    (64 - SF_IDEMPOTENCY_CHANNEL_ID_BITS)
#define SF_IDEMPOTENCY_MAX_CHANNEL_COUNT  ((1 << SF_IDEMPOTENCY_CHANNEL_ID_BITS) - 1)
#define SF_IDEMPOTENCY_MAX_CHANNEL_ID     SF_IDEMPOTENCY_MAX_CHANNEL_COUNT

#define SF_IDEMPOTENCY_SERVER_ID_OFFSET   48
#define SF_IDEMPOTENCY_CHANNEL_ID_OFFSET  32

#define SF_IDEMPOTENCY_NEXT_REQ_ID(server_id, channel_id, seq)    \
    (((int64_t)server_id)  << SF_IDEMPOTENCY_SERVER_ID_OFFSET)  | \
    (((int64_t)channel_id) << SF_IDEMPOTENCY_CHANNEL_ID_OFFSET) | \
    (int64_t)seq

#define SF_IDEMPOTENCY_EXTRACT_SERVER_ID(req_id) \
    (int)((req_id >> SF_IDEMPOTENCY_SERVER_ID_OFFSET) & 0xFFFF)

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif
