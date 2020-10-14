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


#ifndef _SF_IDEMPOTENCY_REQUEST_HTABLE_H
#define _SF_IDEMPOTENCY_REQUEST_HTABLE_H

#include "server_types.h"

#ifdef __cplusplus
extern "C" {
#endif

    void idempotency_request_init(const uint32_t hint_capacity);

    int idempotency_request_htable_add(IdempotencyRequestHTable
            *htable, IdempotencyRequest *request);

    int idempotency_request_htable_remove(IdempotencyRequestHTable *htable,
            const uint64_t req_id);

    void idempotency_request_htable_clear(IdempotencyRequestHTable *htable);

    static inline void idempotency_request_release(IdempotencyRequest *request)
    {
        if (__sync_sub_and_fetch(&request->ref_count, 1) == 0) {
            fast_mblock_free_object(request->allocator, request);
        }
    }

#ifdef __cplusplus
}
#endif

#endif
