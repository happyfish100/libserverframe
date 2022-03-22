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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <pthread.h>
#include "fastcommon/logger.h"
#include "fastcommon/sockopt.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/pthread_func.h"
#include "fastcommon/sched_thread.h"
#include "sf_global.h"
#include "sf_func.h"
#include "sf_ordered_writer.h"

#define deal_binlog_one_record(writer, wb) \
    sf_file_writer_deal_versioned_buffer(&(writer)->fw, &wb->bf, wb->version)

static inline int flush_writer_files(SFOrderedWriterInfo *writer)
{
    int result;

    if ((result=sf_file_writer_flush(&writer->fw)) != 0) {
        return result;
    }

    if (writer->fw.flags & SF_FILE_WRITER_FLAGS_WANT_DONE_VERSION) {
        writer->fw.last_versions.done = writer->fw.last_versions.pending;
    }

    return 0;
}

static inline int deal_versioned_binlog(SFOrderedWriterContext *context)
{
    SFOrderedWriterBuffer *wb;
    int result;

    while (1) {
        if ((wb=sorted_queue_pop(&context->thread.queues.buffer,
                        &context->thread.waiting)) != NULL)
        {
            context->writer.fw.total_count++;
            result = deal_binlog_one_record(&context->writer, wb);
            fast_mblock_free_object(&context->thread.allocators.buffer, wb);
            return result;
        }
    }

    return 0;
}

static int deal_version_chain(SFOrderedWriterContext *context,
        struct fc_queue_info *qinfo)
{
    int result;
    SFWriterVersionEntry *current_ver;
    struct fast_mblock_node *prev_node;
    struct fast_mblock_node *curr_node;
    struct fast_mblock_chain node_chain;

    current_ver = qinfo->head;
    prev_node = NULL;
    do {
        curr_node = fast_mblock_to_node_ptr(current_ver);
        if (prev_node != NULL) {
            prev_node->next = curr_node;
        }
        prev_node = curr_node;

        context->thread.waiting.version = current_ver->version;
        if ((result=deal_versioned_binlog(context)) != 0) {
            return result;
        }
    } while ((current_ver=current_ver->next) != NULL);

    node_chain.head = fast_mblock_to_node_ptr(qinfo->head);
    node_chain.tail = prev_node;
    prev_node->next = NULL;
    fast_mblock_batch_free(&context->thread.allocators.version, &node_chain);
    return flush_writer_files(&context->writer);
}

void sf_ordered_writer_finish(SFOrderedWriterContext *ctx)
{
    int count;

    if (ctx->writer.fw.file.name != NULL) {
        fc_queue_terminate(&ctx->thread.queues.version);

        count = 0;
        while (ctx->thread.running && ++count < 300) {
            fc_sleep_ms(10);
        }

        if (ctx->thread.running) {
            logWarning("file: "__FILE__", line: %d, "
                    "%s binlog write thread still running, exit anyway!",
                    __LINE__, ctx->writer.fw.cfg.subdir_name);
        }

        free(ctx->writer.fw.file.name);
        ctx->writer.fw.file.name = NULL;
    }

    if (ctx->writer.fw.file.fd >= 0) {
        close(ctx->writer.fw.file.fd);
        ctx->writer.fw.file.fd = -1;
    }
}

static void *binlog_writer_func(void *arg)
{
    SFOrderedWriterContext *context;
    SFOrderedWriterThread *thread;
    struct fc_queue_info qinfo;

    context = (SFOrderedWriterContext *)arg;
    thread = &context->thread;

#ifdef OS_LINUX
    {
        char thread_name[64];
        snprintf(thread_name, sizeof(thread_name),
                "%s-writer", thread->name);
        prctl(PR_SET_NAME, thread_name);
    }
#endif

    thread->running = true;
    while (SF_G_CONTINUE_FLAG) {
        fc_queue_pop_to_queue(&thread->queues.version, &qinfo);
        if (qinfo.head== NULL) {
            continue;
        }

        if (deal_version_chain(context, &qinfo) != 0) {
            logCrit("file: "__FILE__", line: %d, "
                    "deal_version_chain fail, "
                    "program exit!", __LINE__);
            sf_terminate_myself();
        }
    }

    thread->running = false;
    return NULL;
}

static int binlog_wbuffer_alloc_init(void *element, void *args)
{
    SFOrderedWriterBuffer *wbuffer;
    SFOrderedWriterInfo *writer;

    wbuffer = (SFOrderedWriterBuffer *)element;
    writer = (SFOrderedWriterInfo *)args;
    wbuffer->bf.alloc_size = writer->fw.cfg.max_record_size;
    wbuffer->bf.buff = (char *)(wbuffer + 1);
    return 0;
}

static int compare_buffer_version(const SFOrderedWriterBuffer *entry1,
        const SFOrderedWriterBuffer *entry2)
{
    return fc_compare_int64(entry1->version, entry2->version);
}

static int sf_ordered_writer_init_thread(SFOrderedWriterContext *context,
        const char *name, const int max_record_size)
{
    const int alloc_elements_once = 1024;
    SFOrderedWriterThread *thread;
    SFOrderedWriterInfo *writer;
    int element_size;
    pthread_t tid;
    int result;

    thread = &context->thread;
    writer = &context->writer;
    snprintf(thread->name, sizeof(thread->name), "%s", name);
    writer->fw.cfg.max_record_size = max_record_size;
    writer->thread = thread;

    if ((result=fast_mblock_init_ex1(&thread->allocators.version,
                    "writer-ver-info", sizeof(SFWriterVersionEntry),
                    8 * 1024, 0, NULL, NULL, true)) != 0)
    {
        return result;
    }

    element_size = sizeof(SFOrderedWriterBuffer) + max_record_size;
    if ((result=fast_mblock_init_ex1(&thread->allocators.buffer,
                    "sorted-wbuffer", element_size, alloc_elements_once,
                    0, binlog_wbuffer_alloc_init, writer, true)) != 0)
    {
        return result;
    }

    if ((result=fc_queue_init(&thread->queues.version, (unsigned long)
                    (&((SFWriterVersionEntry *)NULL)->next))) != 0)
    {
        return result;
    }

    if ((result=sorted_queue_init(&thread->queues.buffer, (unsigned long)
                    (&((SFOrderedWriterBuffer *)NULL)->next),
                    (int (*)(const void *, const void *))
                    compare_buffer_version)) != 0)
    {
        return result;
    }

    return fc_create_thread(&tid, binlog_writer_func,
            context, SF_G_THREAD_STACK_SIZE);
}

int sf_ordered_writer_init(SFOrderedWriterContext *context,
        const char *data_path, const char *subdir_name,
        const int buffer_size, const int max_record_size)
{
    int result;
    if ((result=sf_file_writer_init(&context->writer.fw,
                    data_path, subdir_name, buffer_size)) != 0)
    {
        return result;
    }

    return sf_ordered_writer_init_thread(context,
            subdir_name, max_record_size);
}
