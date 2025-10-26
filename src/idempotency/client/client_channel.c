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

//client_channel.c

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include "fastcommon/logger.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/pthread_func.h"
#include "fastcommon/sched_thread.h"
#include "fastcommon/fc_queue.h"
#include "sf/sf_util.h"
#include "sf/sf_func.h"
#include "sf/sf_nio.h"
#include "sf/sf_global.h"
#include "sf/sf_service.h"
#include "client_channel.h"

typedef struct {
    IdempotencyClientChannel **buckets;
    uint32_t capacity;
    uint32_t count;
    pthread_mutex_t lock;
} ClientChannelHashtable;

typedef struct {
    struct fast_mblock_man channel_allocator;
    ClientChannelHashtable htable;
} ClientChannelContext;

static ClientChannelContext channel_context;

IdempotencyClientConfig g_idempotency_client_cfg = {false, 3, 300};

static int load_client_channel_config(IniFullContext *ini_ctx)
{
    g_idempotency_client_cfg.enabled = iniGetBoolValue(
            ini_ctx->section_name, "enabled",
            ini_ctx->context, false);

    g_idempotency_client_cfg.channel_htable_capacity = iniGetIntValue(
            ini_ctx->section_name, "channel_htable_capacity",
            ini_ctx->context, 1361);
    if (g_idempotency_client_cfg.channel_htable_capacity < 163) {
        logWarning("file: "__FILE__", line: %d, "
                "config file: %s, channel_htable_capacity: %d is "
                "too small, set to 163", __LINE__, ini_ctx->filename,
                g_idempotency_client_cfg.channel_htable_capacity);
        g_idempotency_client_cfg.channel_htable_capacity = 163;
    }

    g_idempotency_client_cfg.channel_heartbeat_interval = iniGetIntValue(
            ini_ctx->section_name, "channel_heartbeat_interval",
            ini_ctx->context, 3);
    if (g_idempotency_client_cfg.channel_heartbeat_interval <= 0) {
        logWarning("file: "__FILE__", line: %d, "
                "config file: %s, channel_heartbeat_interval: %d is "
                "invalid, set to 3", __LINE__, ini_ctx->filename,
                g_idempotency_client_cfg.channel_heartbeat_interval);
        g_idempotency_client_cfg.channel_heartbeat_interval = 3;
    }

    g_idempotency_client_cfg.channel_max_idle_time = iniGetIntValue(
            ini_ctx->section_name, "channel_max_idle_time",
            ini_ctx->context, 300);
    return 0;
}

void idempotency_client_channel_config_to_string_ex(
        char *output, const int size, const bool add_comma)
{
    snprintf(output, size, "channel_htable_capacity=%d, "
            "channel_heartbeat_interval=%ds, "
            "channel_max_idle_time=%ds%s",
            g_idempotency_client_cfg.channel_htable_capacity,
            g_idempotency_client_cfg.channel_heartbeat_interval,
            g_idempotency_client_cfg.channel_max_idle_time,
            (add_comma ? ", " : ""));
}

static int init_htable(ClientChannelHashtable *htable)
{
    int result;
    int bytes;

    if ((result=init_pthread_lock(&htable->lock)) != 0) {
        return result;
    }

    htable->capacity = fc_ceil_prime(g_idempotency_client_cfg.
            channel_htable_capacity);
    bytes = sizeof(IdempotencyClientChannel *) * htable->capacity;
    htable->buckets = (IdempotencyClientChannel **)fc_malloc(bytes);
    if (htable->buckets == NULL) {
        return ENOMEM;
    }
    memset(htable->buckets, 0, bytes);
    htable->count = 0;

    return 0;
}

static int idempotency_channel_alloc_init(void *element, void *args)
{
    int result;
    IdempotencyClientChannel *channel;

    channel = (IdempotencyClientChannel *)element;
    if ((result=fast_mblock_init_ex1(&channel->receipt_allocator,
                    "idempotency-receipt", sizeof(IdempotencyClientReceipt),
                    1024, 0, NULL, NULL, true)) != 0)
    {
        return result;
    }

    if ((result=init_pthread_lock_cond_pair(&channel->lcp)) != 0) {
        return result;
    }

    FC_INIT_LIST_HEAD(&channel->dlink);
    return fc_queue_init(&channel->queue, (long)
            (&((IdempotencyClientReceipt *)NULL)->next));
}

int client_channel_init(IniFullContext *ini_ctx)
{
    int result;

    if ((result=load_client_channel_config(ini_ctx)) != 0) {
        return result;
    }

    if ((result=fast_mblock_init_ex1(&channel_context.channel_allocator,
                    "channel-info", sizeof(IdempotencyClientChannel),
                    64, 0, idempotency_channel_alloc_init, NULL, true)) != 0)
    {
        return result;
    }

    if ((result=init_htable(&channel_context.htable)) != 0) {
        return result;
    }

    return 0;
}

void client_channel_destroy()
{
}

static struct fast_task_info *alloc_channel_task(IdempotencyClientChannel
        *channel, const uint32_t hash_code, const FCCommunicationType comm_type,
        const char *server_ip, const uint16_t port, int *err_no)
{
    struct fast_task_info *task;
    SFAddressFamilyHandler *fh;
    SFNetworkHandler *handler;

    if (is_ipv6_addr(server_ip)) {
        fh = g_sf_context.handlers + SF_IPV6_ADDRESS_FAMILY_INDEX;
    } else {
        fh = g_sf_context.handlers + SF_IPV4_ADDRESS_FAMILY_INDEX;
    }

    if (comm_type == fc_comm_type_sock) {
        handler = fh->handlers + SF_SOCKET_NETWORK_HANDLER_INDEX;
    } else {
        handler = fh->handlers + SF_RDMACM_NETWORK_HANDLER_INDEX;
    }
    if ((task=sf_alloc_init_task(handler, -1)) == NULL) {
        *err_no = ENOMEM;
        return NULL;
    }

    fc_safe_strcpy(task->server_ip, server_ip);
    task->port = port;
    task->arg = channel;
    task->thread_data = g_sf_context.thread_data +
        hash_code % g_sf_context.work_threads;
    channel->in_ioevent = 1;
    channel->last_connect_time = g_current_time;
    if ((*err_no=sf_nio_notify(task, SF_NIO_STAGE_CONNECT)) != 0) {
        channel->in_ioevent = 0;   //rollback
        __sync_sub_and_fetch(&task->reffer_count, 1);
        free_queue_push(task);
        return NULL;
    }
    return task;
}

int idempotency_client_channel_check_reconnect(
        IdempotencyClientChannel *channel)
{
    int result;
    char formatted_ip[FORMATTED_IP_SIZE];

#if IOEVENT_USE_URING
    if (FC_ATOMIC_GET(channel->task->reffer_count) > 1) {
        return 0;
    }
#endif

    if (!__sync_bool_compare_and_swap(&channel->in_ioevent, 0, 1)) {
        return 0;
    }

    if (channel->last_connect_time >= g_current_time) {
        sleep(1);
        channel->last_connect_time = g_current_time;
    }

    if (FC_LOG_BY_LEVEL(LOG_DEBUG)) {
        format_ip_address(channel->task->server_ip, formatted_ip);
        logDebug("file: "__FILE__", line: %d, "
                "trigger connect to server %s:%u", __LINE__,
                formatted_ip, channel->task->port);
    }

    if (channel->task->event.fd >= 0) {
        channel->task->handler->close_connection(channel->task);
    }
    __sync_bool_compare_and_swap(&channel->task->canceled, 1, 0);
    if ((result=sf_nio_notify(channel->task, SF_NIO_STAGE_CONNECT)) == 0) {
        channel->last_connect_time = g_current_time;
        channel->last_report_time = g_current_time;
    } else {
        __sync_bool_compare_and_swap(&channel->in_ioevent, 1, 0); //rollback
    }
    return result;
}

struct idempotency_client_channel *idempotency_client_channel_get(
        const FCCommunicationType comm_type, const char *server_ip,
        const uint16_t server_port, const int timeout, int *err_no)
{
    int r;
    int key_len;
    bool found;
    char key[64];
    uint32_t hash_code;
    IdempotencyClientChannel **bucket;
    IdempotencyClientChannel *previous;
    IdempotencyClientChannel *current;
    IdempotencyClientChannel *channel;

    key_len = strlen(server_ip);
    memcpy(key, server_ip, key_len);
    *(key + key_len++) = '-';
    key_len += fc_itoa(server_port, key + key_len);
    hash_code = fc_simple_hash(key, key_len);
    bucket = channel_context.htable.buckets +
        hash_code % channel_context.htable.capacity;
    previous = NULL;
    channel = NULL;
    *err_no = 0;
    found = false;

    PTHREAD_MUTEX_LOCK(&channel_context.htable.lock);
    do {
        current = *bucket;
        while (current != NULL) {
            r = conn_pool_compare_ip_and_port(current->task->server_ip,
                    current->task->port, server_ip, server_port);
            if (r == 0) {
                channel = current;
                found = true;
                break;
            } else if (r > 0) {
                break;
            }

            previous = current;
            current = current->next;
        }

        if (found) {
            break;
        }

        channel = (IdempotencyClientChannel *)fast_mblock_alloc_object(
                &channel_context.channel_allocator);
        if (channel == NULL) {
            *err_no = ENOMEM;
            break;
        }

        channel->task = alloc_channel_task(channel, hash_code,
                comm_type, server_ip, server_port, err_no);
        if (channel->task == NULL) {
            fast_mblock_free_object(&channel_context.
                    channel_allocator, channel);
            channel = NULL;
            break;
        }

        if (previous == NULL) {
            channel->next = *bucket;
            *bucket = channel;
        } else {
            channel->next = previous->next;
            previous->next = channel;
        }
        channel_context.htable.count++;
    } while (0);
    PTHREAD_MUTEX_UNLOCK(&channel_context.htable.lock);

    if (channel != NULL) {
        if ((*err_no=idempotency_client_channel_check_wait_ex(
                        channel, timeout)) != 0)
        {
            return NULL;
        }
    }

    return channel;
}

int idempotency_client_channel_push(struct idempotency_client_channel *channel,
        const uint64_t req_id)
{
    IdempotencyClientReceipt *receipt;
    bool notify;

    receipt = (IdempotencyClientReceipt *)fast_mblock_alloc_object(
            &channel->receipt_allocator);
    if (receipt == NULL) {
        return ENOMEM;
    }

    receipt->req_id = req_id;
    fc_queue_push_ex(&channel->queue, receipt, &notify);
    if (notify) {
        if (FC_ATOMIC_GET(channel->in_ioevent)) {
            if (FC_ATOMIC_GET(channel->established)) {
                sf_nio_notify(channel->task, SF_NIO_STAGE_CONTINUE);
            }
        } else {
            return idempotency_client_channel_check_reconnect(channel);
        }
    }

    return 0;
}
