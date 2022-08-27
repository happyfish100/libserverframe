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

#include "sf_shared_mbuffer.h"

static int sf_shared_mbuffer_alloc_init(void *element, void *args)
{
    SFSharedMBuffer *buffer;

    buffer = (SFSharedMBuffer *)element;
    buffer->buff = (char *)(buffer + 1);
    buffer->ctx = (SFSharedMBufferContext *)args;
    return 0;
}

int sf_shared_mbuffer_init_ex(SFSharedMBufferContext *context,
        const char *name_prefix, const int buff_extra_size,
        const int min_buff_size, const int max_buff_size,
        const int min_alloc_once, const int64_t memory_limit,
        const bool need_lock)
{
    const double expect_usage_ratio = 0.75;
    const int reclaim_interval = 1;
    struct fast_region_info regions[32];
    struct fast_mblock_object_callbacks object_callbacks;
    int count;
    int start;
    int end;
    int alloc_once;
    int buff_size;
    int i;

    alloc_once = (4 * 1024 * 1024) / max_buff_size;
    if (alloc_once == 0) {
        alloc_once = min_alloc_once;
    } else {
        i = min_alloc_once;
        while (i < alloc_once) {
            i *= 2;
        }
        alloc_once = i;
    }

    count = 1;
    buff_size = min_buff_size;
    while (buff_size < max_buff_size) {
        buff_size *= 2;
        ++count;
        alloc_once *= 2;
    }

    buff_size = min_buff_size;
    start = 0;
    end = buff_extra_size + buff_size;
    FAST_ALLOCATOR_INIT_REGION(regions[0], start, end,
            end - start, alloc_once);

    //logInfo("[1] start: %d, end: %d, alloc_once: %d", start, end, alloc_once);

    start = end;
    for (i=1; i<count; i++) {
        buff_size *= 2;
        alloc_once /= 2;
        end = buff_extra_size + buff_size;
        FAST_ALLOCATOR_INIT_REGION(regions[i], start, end,
                end - start, alloc_once);
        //logInfo("[%d] start: %d, end: %d, alloc_once: %d", i + 1, start, end, alloc_once);
        start = end;
    }

    object_callbacks.init_func = sf_shared_mbuffer_alloc_init;
    object_callbacks.destroy_func = NULL;
    object_callbacks.args = context;
    return fast_allocator_init_ex(&context->allocator, name_prefix,
            sizeof(SFSharedMBuffer), &object_callbacks, regions, count,
            memory_limit, expect_usage_ratio, reclaim_interval, need_lock);
}

void sf_shared_mbuffer_destroy(SFSharedMBufferContext *context)
{
    fast_allocator_destroy(&context->allocator);
}
