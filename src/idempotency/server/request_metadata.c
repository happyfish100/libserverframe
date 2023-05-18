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

#include <limits.h>
#include <sys/stat.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/fc_atomic.h"
#include "sf/sf_global.h"
#include "request_metadata.h"

static struct {
    int process_interval_ms;
    int master_side_timeout;  //in seconds
    struct {
        IdempotencyRequestMetadataContext *head;
        IdempotencyRequestMetadataContext *tail;
    } list;
} g_request_metadata = {1000, 300, {NULL, NULL}};


#define CHECK_MASTER_METADATA(meta) \
    (meta != NULL && g_current_time - (long)meta->enqueue_time > \
     g_request_metadata.master_side_timeout)

static void process_master_side(IdempotencyRequestMetadataContext *ctx)
{
    struct fast_mblock_chain chain;
    struct fast_mblock_node *node;
    int count = 0;

    chain.head = chain.tail = NULL;
    PTHREAD_MUTEX_LOCK(&ctx->lock);
    if (CHECK_MASTER_METADATA(ctx->list.head)) {
        do {
            node = fast_mblock_to_node_ptr(ctx->list.head);
            if (chain.head == NULL) {
                chain.head = node;
            } else {
                chain.tail->next = node;
            }
            chain.tail = node;

            ++count;
            ctx->list.head = ctx->list.head->next;
        } while (CHECK_MASTER_METADATA(ctx->list.head));

        if (ctx->list.head == NULL) {
            ctx->list.tail = NULL;
        }
        chain.tail->next = NULL;
    }

    if (chain.head != NULL) {
        fast_mblock_batch_free(&ctx->allocator, &chain);
    }
    PTHREAD_MUTEX_UNLOCK(&ctx->lock);

    if (count > 0) {
        logInfo("#######func: %s, deal count: %d", __FUNCTION__, count);
    }
}

#define CHECK_SLAVE_METADATA(meta, dv) \
    (meta != NULL && meta->data_version <= dv)

static void process_slave_side(IdempotencyRequestMetadataContext *ctx,
        const int64_t data_version)
{
    struct fast_mblock_chain chain;
    struct fast_mblock_node *node;

    chain.head = chain.tail = NULL;
    PTHREAD_MUTEX_LOCK(&ctx->lock);
    if (CHECK_SLAVE_METADATA(ctx->list.head, data_version)) {
        do {
            node = fast_mblock_to_node_ptr(ctx->list.head);
            if (chain.head == NULL) {
                chain.head = node;
            } else {
                chain.tail->next = node;
            }
            chain.tail = node;

            ctx->list.head = ctx->list.head->next;
        } while (CHECK_SLAVE_METADATA(ctx->list.head, data_version));

        if (ctx->list.head == NULL) {
            ctx->list.tail = NULL;
        }
        chain.tail->next = NULL;
    }

    if (chain.head != NULL) {
        fast_mblock_batch_free(&ctx->allocator, &chain);
    }
    PTHREAD_MUTEX_UNLOCK(&ctx->lock);
}

static void *thread_run(void *arg)
{
    IdempotencyRequestMetadataContext *ctx;
    int64_t data_version;

#ifdef OS_LINUX
    prctl(PR_SET_NAME, "idemp-req-meta");
#endif

    ctx = g_request_metadata.list.head;
    while (SF_G_CONTINUE_FLAG) {
        fc_sleep_ms(g_request_metadata.process_interval_ms);

        if (ctx->is_master_callback.func(ctx->is_master_callback.
                    arg, &data_version))
        {
            process_master_side(ctx);
        } else if (data_version > 0) {
            process_slave_side(ctx, data_version);
        }

        ctx = ctx->next;
        if (ctx == NULL) {
            ctx = g_request_metadata.list.head;
        }
    }

    return NULL;
}

int idempotency_request_metadata_init(IdempotencyRequestMetadataContext
        *ctx, sf_is_master_callback is_master_callback, void *arg)
{
    int result;

    if ((result=fast_mblock_init_ex1(&ctx->allocator, "req-metadata-info",
                    sizeof(IdempotencyRequestMetadata), 8192, 0,
                    NULL, NULL, false)) != 0)
    {
        return result;
    }

    if ((result=init_pthread_lock(&ctx->lock)) != 0) {
        return result;
    }

    ctx->is_master_callback.func = is_master_callback;
    ctx->is_master_callback.arg = arg;
    ctx->list.head = ctx->list.tail = NULL;

    ctx->next = NULL;
    if (g_request_metadata.list.head == NULL) {
        g_request_metadata.list.head = ctx;
    } else {
        g_request_metadata.list.tail->next = ctx;
    }
    g_request_metadata.list.tail = ctx;

    return 0;
}

int idempotency_request_metadata_start(const int process_interval_ms,
            const int master_side_timeout)
{
    pthread_t tid;

    if (g_request_metadata.list.head == NULL) {
        logError("file: "__FILE__", line: %d, "
                "list is empty!", __LINE__);
        return ENOENT;
    }

    if (process_interval_ms <= 0) {
        logError("file: "__FILE__", line: %d, "
                "invalid process interval: %d!",
                __LINE__, process_interval_ms);
        return EINVAL;
    }

    if (master_side_timeout <= 0) {
        logError("file: "__FILE__", line: %d, "
                "invalid master side timeout: %d!",
                __LINE__, master_side_timeout);
        return EINVAL;
    }

    g_request_metadata.process_interval_ms = process_interval_ms;
    g_request_metadata.master_side_timeout = master_side_timeout;
    return fc_create_thread(&tid, thread_run, NULL,
            SF_G_THREAD_STACK_SIZE);
}

int idempotency_request_metadata_add(IdempotencyRequestMetadataContext
        *ctx, const SFRequestMetadata *metadata, const int n)
{
    IdempotencyRequestMetadata *idemp_meta;

    PTHREAD_MUTEX_LOCK(&ctx->lock);
    do {
        if ((idemp_meta=fast_mblock_alloc_object(&ctx->allocator)) == NULL) {
            break;
        }

        idemp_meta->req_id = metadata->req_id;
        idemp_meta->data_version = metadata->data_version;
        idemp_meta->n = n;
        idemp_meta->enqueue_time = g_current_time;
        idemp_meta->next = NULL;

        if (ctx->list.head == NULL) {
            ctx->list.head = idemp_meta;
        } else {
            ctx->list.tail->next = idemp_meta;
        }
        ctx->list.tail = idemp_meta;
    } while (0);
    PTHREAD_MUTEX_UNLOCK(&ctx->lock);

    return (idemp_meta != NULL ? 0 : ENOMEM);
}

int idempotency_request_metadata_get(IdempotencyRequestMetadataContext
        *ctx, const int64_t req_id, int64_t *data_version, int *n)
{
    int result;
    IdempotencyRequestMetadata *meta;

    result = ENOENT;
    PTHREAD_MUTEX_LOCK(&ctx->lock);
    meta = ctx->list.head;
    while (meta != NULL) {
        if (req_id == meta->req_id) {
            result = 0;
            *data_version = meta->data_version;
            if (n != NULL) {
                *n = meta->n;
            }
            break;
        }
        meta = meta->next;
    }
    PTHREAD_MUTEX_UNLOCK(&ctx->lock);

    return result;
}
