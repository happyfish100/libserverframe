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


#ifndef _SF_IDEMPOTENCY_CHANNEL_HTABLE_H
#define _SF_IDEMPOTENCY_CHANNEL_HTABLE_H

#include "server_types.h"

typedef struct channel_shared_locks {
    pthread_mutex_t *locks;
    uint32_t count;
} ChannelSharedLocks;

typedef struct idempotency_channel_htable {
    IdempotencyChannel **buckets;
    uint32_t capacity;
    uint32_t count;
} IdempotencyChannelHTable;

typedef struct channel_htable_context {
    ChannelSharedLocks shared_locks;
    IdempotencyChannelHTable htable;
} ChannelHTableContext;

#ifdef __cplusplus
extern "C" {
#endif

    int idempotency_channel_htable_init(ChannelHTableContext *ctx,
            const uint32_t shared_lock_count, const uint32_t hint_capacity);

    int idempotency_channel_htable_add(ChannelHTableContext *ctx,
            IdempotencyChannel *channel);

    IdempotencyChannel *idempotency_channel_htable_remove(
            ChannelHTableContext *ctx, const uint32_t channel_id);

    IdempotencyChannel *idempotency_channel_htable_find(
            ChannelHTableContext *ctx, const uint32_t channel_id);

#ifdef __cplusplus
}
#endif

#endif
