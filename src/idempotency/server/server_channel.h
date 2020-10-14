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


#ifndef _SF_IDEMPOTENCY_SERVER_CHANNEL_H
#define _SF_IDEMPOTENCY_SERVER_CHANNEL_H

#include "fastcommon/fast_timer.h"
#include "request_htable.h"

#ifdef __cplusplus
extern "C" {
#endif

    int idempotency_channel_init(const uint32_t max_channel_id,
            const int request_hint_capacity,
            const uint32_t reserve_interval,
            const uint32_t shared_lock_count);

    IdempotencyChannel *idempotency_channel_alloc(const uint32_t channel_id,
            const int key);

    void idempotency_channel_release(IdempotencyChannel *channel,
            const bool is_holder);

    IdempotencyChannel *idempotency_channel_find_and_hold(
            const uint32_t channel_id, const int key, int *result);

    void idempotency_channel_free(IdempotencyChannel *channel);

    static inline int idempotency_channel_add_request(IdempotencyChannel *
            channel, IdempotencyRequest *request)
    {
        return idempotency_request_htable_add(
                &channel->request_htable, request);
    }

    static inline int idempotency_channel_remove_request(
            IdempotencyChannel *channel, const uint64_t req_id)
    {
        return idempotency_request_htable_remove(
                &channel->request_htable, req_id);
    }

    int idempotency_request_alloc_init(void *element, void *args);

#ifdef __cplusplus
}
#endif

#endif
