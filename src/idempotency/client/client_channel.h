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

//client_channel.h

#ifndef IDEMPOTENCY_CLIENT_CHANNEL_H
#define IDEMPOTENCY_CLIENT_CHANNEL_H

#include "fastcommon/ini_file_reader.h"
#include "fastcommon/pthread_func.h"
#include "fastcommon/sched_thread.h"
#include "fastcommon/fc_atomic.h"
#include "client_types.h"

#ifdef __cplusplus
extern "C" {
#endif

extern IdempotencyClientConfig g_idempotency_client_cfg;

int client_channel_init(IniFullContext *ini_ctx);
void client_channel_destroy();

#define idempotency_client_channel_config_to_string(output, size) \
    idempotency_client_channel_config_to_string_ex(output, size, false)

void idempotency_client_channel_config_to_string_ex(
        char *output, const int size, const bool add_comma);

struct idempotency_client_channel *idempotency_client_channel_get(
        const char *server_ip, const uint16_t server_port,
        const int timeout, int *err_no);

static inline uint64_t idempotency_client_channel_next_seq_id(
        struct idempotency_client_channel *channel)
{
    return __sync_add_and_fetch(&channel->next_req_id, 1);
}

int idempotency_client_channel_push(struct idempotency_client_channel *channel,
        const uint64_t req_id);

int idempotency_client_channel_check_reconnect(
        IdempotencyClientChannel *channel);

static inline void idempotency_client_channel_set_id_key(
        IdempotencyClientChannel *channel, const uint32_t new_id,
        const uint32_t new_key)
{
    uint32_t old_id;
    uint32_t old_key;

    old_id = __sync_add_and_fetch(&channel->id, 0);
    old_key = __sync_add_and_fetch(&channel->key, 0);
    FC_ATOMIC_CAS(channel->id, old_id, new_id);
    FC_ATOMIC_CAS(channel->key, old_key, new_key);
}

#define idempotency_client_channel_check_wait(channel)  \
    idempotency_client_channel_check_wait_ex(channel, 1)

static inline int idempotency_client_channel_check_wait_ex(
        struct idempotency_client_channel *channel, const int timeout)
{
    struct timespec ts;

    if (__sync_add_and_fetch(&channel->established, 0)) {
        return 0;
    }

    idempotency_client_channel_check_reconnect(channel);
    PTHREAD_MUTEX_LOCK(&channel->lc_pair.lock);
    ts.tv_sec = get_current_time() + timeout;
    ts.tv_nsec = 0;
    pthread_cond_timedwait(&channel->lc_pair.cond,
            &channel->lc_pair.lock, &ts);
    PTHREAD_MUTEX_UNLOCK(&channel->lc_pair.lock);

    return __sync_add_and_fetch(&channel->established, 0) ? 0 : ETIMEDOUT;
}

#ifdef __cplusplus
}
#endif

#endif
