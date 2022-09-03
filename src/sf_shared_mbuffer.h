/*
 * Copyright (c) 2020 YuQing <384681@qq.com>
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

#ifndef _SF_SHARED_MBUFFER_H__
#define _SF_SHARED_MBUFFER_H__

#include "fastcommon/fc_list.h"
#include "fastcommon/fast_task_queue.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/fast_allocator.h"

typedef struct sf_shared_mbuffer_context {
    struct fast_allocator_context allocator;
} SFSharedMBufferContext;

typedef struct sf_shared_mbuffer {
    int length;
    volatile int reffer_count;
    SFSharedMBufferContext *ctx;
    char buff[0];  //must be last
} SFSharedMBuffer;

#ifdef __cplusplus
extern "C" {
#endif

#define sf_shared_mbuffer_init(context, name_prefix, buff_extra_size, \
        min_buff_size, max_buff_size, min_alloc_once, memory_limit)   \
    sf_shared_mbuffer_init_ex(context, name_prefix, buff_extra_size,  \
        min_buff_size, max_buff_size, min_alloc_once, memory_limit, true)

int sf_shared_mbuffer_init_ex(SFSharedMBufferContext *context,
        const char *name_prefix, const int buff_extra_size,
        const int min_buff_size, const int max_buff_size,
        const int min_alloc_once, const int64_t memory_limit,
        const bool need_lock);

void sf_shared_mbuffer_destroy(SFSharedMBufferContext *context);

#define sf_shared_mbuffer_alloc(context, buffer_size)  \
    sf_shared_mbuffer_alloc_ex(context, buffer_size, 1)

static inline SFSharedMBuffer *sf_shared_mbuffer_alloc_ex(
        SFSharedMBufferContext *context, const int buffer_size,
        const int init_reffer_count)
{
    SFSharedMBuffer *buffer;
    int sleep_ms;

    sleep_ms = 5;
    while ((buffer=fast_allocator_alloc(&context->allocator,
                    buffer_size)) == NULL)
    {
        if (sleep_ms < 100) {
            sleep_ms *= 2;
        }
        fc_sleep_ms(sleep_ms);
    }

    if (init_reffer_count > 0) {
        __sync_add_and_fetch(&buffer->reffer_count, init_reffer_count);
    }

    /*
    logInfo("file: "__FILE__", line: %d, "
            "alloc shared buffer: %p, buff: %p, reffer_count: %d",
            __LINE__, buffer, buffer->buff, __sync_add_and_fetch(&buffer->reffer_count, 0));
            */

    return buffer;
}

static inline void sf_shared_mbuffer_hold(SFSharedMBuffer *buffer)
{
    __sync_add_and_fetch(&buffer->reffer_count, 1);
}

static inline void sf_shared_mbuffer_release(SFSharedMBuffer *buffer)
{
    if (__sync_sub_and_fetch(&buffer->reffer_count, 1) == 0) {
        /*
        logInfo("file: "__FILE__", line: %d, "
                "free shared buffer: %p", __LINE__, buffer);
                */
        fast_allocator_free(&buffer->ctx->allocator, buffer);
    }
}

static inline void sf_release_task_shared_mbuffer(struct fast_task_info *task)
{
    SFSharedMBuffer *mbuffer;
    mbuffer = fc_list_entry(task->recv_body, SFSharedMBuffer, buff);
    sf_shared_mbuffer_release(mbuffer);
    task->recv_body = NULL;
}

#ifdef __cplusplus
}
#endif

#endif
