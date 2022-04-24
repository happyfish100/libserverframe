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
#include "sf_binlog_writer.h"

#define ERRNO_THREAD_EXIT  -1000

static inline void binlog_writer_set_next_version(SFBinlogWriterInfo *writer,
        const uint64_t next_version)
{
    writer->version_ctx.next = next_version;
    if (writer->fw.flags & SF_FILE_WRITER_FLAGS_WANT_DONE_VERSION) {
        writer->fw.last_versions.done = next_version - 1;
    }
}

#define deal_binlog_one_record(wb) \
    sf_file_writer_deal_versioned_buffer(&wb->writer->fw, \
            &wb->bf, wb->version.last)

#define GET_WBUFFER_VERSION_COUNT(wb)  \
        (((wb)->version.last - (wb)->version.first) + 1)

#define DEAL_CURRENT_VERSION_WBUFFER(writer, wb) \
    do {  \
        if ((result=deal_binlog_one_record(wb)) != 0) {  \
            return result;  \
        } \
        writer->version_ctx.next += GET_WBUFFER_VERSION_COUNT(wb); \
        fast_mblock_free_object(&writer->thread->mblock, wb);   \
    } while (0)

static int deal_record_by_version(SFBinlogWriterBuffer *wb)
{
    SFBinlogWriterInfo *writer;
    SFBinlogWriterBuffer *current;
    SFBinlogWriterBuffer *previous;
    SFBinlogWriterSlot *slot;
    int result;

    writer = wb->writer;
    if (wb->version.first < writer->version_ctx.next) {
        logError("file: "__FILE__", line: %d, subdir_name: %s, "
                "current version: %"PRId64" is too small which "
                "less than %"PRId64", tag: %"PRId64", buffer(%d): %.*s",
                __LINE__, writer->fw.cfg.subdir_name, wb->version.first,
                writer->version_ctx.next, wb->tag, wb->bf.length,
                wb->bf.length, wb->bf.buff);
        fast_mblock_free_object(&writer->thread->mblock, wb);
        return 0;
    }

    /*
    logInfo("%s wb version===== %"PRId64", next: %"PRId64", writer: %p",
            writer->fw.cfg.subdir_name, wb->version.first,
            writer->version_ctx.next, writer);
            */


    if (wb->version.first == writer->version_ctx.next) {
        DEAL_CURRENT_VERSION_WBUFFER(writer, wb);

        slot = writer->version_ctx.ring.slots +
            writer->version_ctx.next % writer->version_ctx.ring.size;
        while (slot->head.next != NULL && slot->head.next->
                version.first == writer->version_ctx.next)
        {
            current = slot->head.next;
            slot->head.next = current->next;

            DEAL_CURRENT_VERSION_WBUFFER(writer, current);
            writer->version_ctx.ring.waiting_count--;

            slot = writer->version_ctx.ring.slots + writer->
                version_ctx.next % writer->version_ctx.ring.size;
        }

        return 0;
    }

    slot = writer->version_ctx.ring.slots + wb->version.first %
        writer->version_ctx.ring.size;
    if (slot->head.next == NULL) {
        wb->next = NULL;
        slot->head.next = wb;
    } else if (wb->version.first < slot->head.next->version.first) {
        wb->next = slot->head.next;
        slot->head.next = wb;
    } else {
        previous = slot->head.next;
        while (previous->next != NULL && wb->version.first >
                previous->next->version.first)
        {
            previous = previous->next;
        }

        wb->next = previous->next;
        previous->next = wb;
    }

    writer->version_ctx.ring.waiting_count++;
    if (writer->version_ctx.ring.waiting_count >
            writer->version_ctx.ring.max_waitings)
    {
        writer->version_ctx.ring.max_waitings =
            writer->version_ctx.ring.waiting_count;
    }

    return 0;
}

static inline void add_to_flush_writer_queue(SFBinlogWriterThread *thread,
        SFBinlogWriterInfo *writer)
{
    if (writer->flush.in_queue) {
        return;
    }

    writer->flush.in_queue = true;
    writer->flush.next = NULL;
    if (thread->flush_writers.head == NULL) {
        thread->flush_writers.head = writer;
    } else {
        thread->flush_writers.tail->flush.next = writer;
    }
    thread->flush_writers.tail = writer;
}

static inline int flush_writer_files(SFBinlogWriterThread *thread)
{
    struct sf_binlog_writer_info *writer;
    int result;

    writer = thread->flush_writers.head;
    while (writer != NULL) {
        if ((result=sf_file_writer_flush(&writer->fw)) != 0) {
            return result;
        }

        if (writer->fw.flags & SF_FILE_WRITER_FLAGS_WANT_DONE_VERSION) {
            writer->fw.last_versions.done = writer->fw.last_versions.pending;
        }
        writer->flush.in_queue = false;
        writer = writer->flush.next;
    }

    thread->flush_writers.head = thread->flush_writers.tail = NULL;
    return 0;
}

static int deal_binlog_records(SFBinlogWriterThread *thread,
        SFBinlogWriterBuffer *wb_head)
{
    int result;
    SFBinlogWriterBuffer *wbuffer;
    SFBinlogWriterBuffer *current;

    wbuffer = wb_head;
    do {
        current = wbuffer;
        wbuffer = wbuffer->next;

        switch (current->type) {
            case SF_BINLOG_BUFFER_TYPE_CHANGE_ORDER_TYPE:
                current->writer->order_by = current->version.first;
                fast_mblock_free_object(&current->writer->
                        thread->mblock, current);
                break;
            case SF_BINLOG_BUFFER_TYPE_NOTIFY_EXIT:
                flush_writer_files(thread);
                return ERRNO_THREAD_EXIT;
            case SF_BINLOG_BUFFER_TYPE_SET_NEXT_VERSION:
                if (current->writer->order_by !=
                        SF_BINLOG_WRITER_TYPE_ORDER_BY_VERSION)
                {
                    logWarning("file: "__FILE__", line: %d, "
                            "subdir_name: %s, invalid order by: %d != %d, "
                            "maybe some mistake happen", __LINE__,
                            current->writer->fw.cfg.subdir_name,
                            current->writer->order_by,
                            SF_BINLOG_WRITER_TYPE_ORDER_BY_VERSION);
                }

                if (current->writer->version_ctx.ring.waiting_count != 0) {
                    logWarning("file: "__FILE__", line: %d, "
                            "subdir_name: %s, ring not empty, "
                            "maybe some mistake happen", __LINE__,
                            current->writer->fw.cfg.subdir_name);
                }

                logDebug("file: "__FILE__", line: %d, "
                        "subdir_name: %s, set next version to %"PRId64,
                        __LINE__, current->writer->fw.cfg.subdir_name,
                        current->version.first);

                if (current->writer->version_ctx.next !=
                        current->version.first)
                {
                    binlog_writer_set_next_version(current->writer,
                            current->version.first);
                    current->writer->version_ctx.change_count++;
                }
                fast_mblock_free_object(&current->writer->
                        thread->mblock, current);
                break;

            default:
                current->writer->fw.total_count++;
                add_to_flush_writer_queue(thread, current->writer);

                if (current->writer->order_by ==
                        SF_BINLOG_WRITER_TYPE_ORDER_BY_VERSION)
                {
                    /* NOTE: current maybe be released in the deal function */
                    if ((result=deal_record_by_version(current)) != 0) {
                        return result;
                    }
                } else {
                    if ((result=deal_binlog_one_record(current)) != 0) {
                        return result;
                    }

                    fast_mblock_free_object(&current->writer->
                            thread->mblock, current);
                }
                break;
        }
    } while (wbuffer != NULL);

    return flush_writer_files(thread);
}

void sf_binlog_writer_finish(SFBinlogWriterInfo *writer)
{
    SFBinlogWriterBuffer *wb_head;
    int count;

    if (writer->fw.file.name != NULL) {
        while (writer->thread->running && !fc_queue_empty(
                    &writer->thread->queue))
        {
            fc_sleep_ms(10);
        }
        if (writer->thread->running) {
            sf_binlog_writer_notify_exit(writer);
        }

        count = 0;
        while (writer->thread->running && ++count < 500) {
            fc_sleep_ms(10);
        }
        
        if (writer->thread->running) {
            logWarning("file: "__FILE__", line: %d, "
                    "%s binlog write thread still running, "
                    "exit anyway!", __LINE__, writer->fw.cfg.subdir_name);
        }

        wb_head = (SFBinlogWriterBuffer *)fc_queue_try_pop_all(
                &writer->thread->queue);
        if (wb_head != NULL) {
            deal_binlog_records(writer->thread, wb_head);
        }

        free(writer->fw.file.name);
        writer->fw.file.name = NULL;
    }

    if (writer->fw.file.fd >= 0) {
        close(writer->fw.file.fd);
        writer->fw.file.fd = -1;
    }
}

static void *binlog_writer_func(void *arg)
{
    SFBinlogWriterThread *thread;
    SFBinlogWriterBuffer *wb_head;
    int result;

    thread = (SFBinlogWriterThread *)arg;

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
        wb_head = (SFBinlogWriterBuffer *)fc_queue_pop_all(&thread->queue);
        if (wb_head == NULL) {
            continue;
        }

        if ((result=deal_binlog_records(thread, wb_head)) != 0) {
            if (result != ERRNO_THREAD_EXIT) {
                logCrit("file: "__FILE__", line: %d, "
                        "deal_binlog_records fail, "
                        "program exit!", __LINE__);
                sf_terminate_myself();
            }
            break;
        }
    }

    thread->running = false;
    return NULL;
}

static int binlog_wbuffer_alloc_init(void *element, void *args)
{
    SFBinlogWriterBuffer *wbuffer;
    SFBinlogWriterInfo *writer;

    wbuffer = (SFBinlogWriterBuffer *)element;
    writer = (SFBinlogWriterInfo *)args;
    wbuffer->writer = writer;
    wbuffer->bf.alloc_size = writer->fw.cfg.max_record_size;
    if (writer->thread->use_fixed_buffer_size) {
        wbuffer->bf.buff = (char *)(wbuffer + 1);
    } else {
        wbuffer->bf.buff = (char *)fc_malloc(writer->fw.cfg.max_record_size);
        if (wbuffer->bf.buff == NULL) {
            return ENOMEM;
        }
    }
    return 0;
}

static void binlog_wbuffer_destroy_func(void *element, void *args)
{
    SFBinlogWriterBuffer *wbuffer;
    wbuffer = (SFBinlogWriterBuffer *)element;
    if (wbuffer->bf.buff != NULL) {
        free(wbuffer->bf.buff);
    }
}

int sf_binlog_writer_init_normal(SFBinlogWriterInfo *writer,
        const char *data_path, const char *subdir_name,
        const int buffer_size)
{
    memset(writer, 0, sizeof(*writer));
    writer->order_by = SF_BINLOG_WRITER_TYPE_ORDER_BY_NONE;
    return sf_file_writer_init(&writer->fw, data_path,
            subdir_name, buffer_size);
}

int sf_binlog_writer_init_by_version(SFBinlogWriterInfo *writer,
        const char *data_path, const char *subdir_name,
        const uint64_t next_version, const int buffer_size,
        const int ring_size)
{
    int bytes;

    bytes = sizeof(SFBinlogWriterSlot) * ring_size;
    writer->version_ctx.ring.slots = (SFBinlogWriterSlot *)fc_malloc(bytes);
    if (writer->version_ctx.ring.slots == NULL) {
        return ENOMEM;
    }
    memset(writer->version_ctx.ring.slots, 0, bytes);
    writer->version_ctx.ring.size = ring_size;
    writer->version_ctx.ring.waiting_count = 0;
    writer->version_ctx.ring.max_waitings = 0;
    writer->version_ctx.change_count = 0;
    writer->order_by = SF_BINLOG_WRITER_TYPE_ORDER_BY_VERSION;

    binlog_writer_set_next_version(writer, next_version);
    writer->flush.in_queue = false;
    return sf_file_writer_init(&writer->fw, data_path,
            subdir_name, buffer_size);
}

int sf_binlog_writer_init_thread_ex(SFBinlogWriterThread *thread,
        const char *name, SFBinlogWriterInfo *writer, const short order_mode,
        const int max_record_size, const int writer_count,
        const bool use_fixed_buffer_size)
{
    const int alloc_elements_once = 1024;
    int result;
    int element_size;
    pthread_t tid;
    struct fast_mblock_object_callbacks callbacks;

    snprintf(thread->name, sizeof(thread->name), "%s", name);
    thread->order_mode = order_mode;
    thread->use_fixed_buffer_size = use_fixed_buffer_size;
    writer->fw.cfg.max_record_size = max_record_size;
    writer->thread = thread;

    callbacks.init_func = binlog_wbuffer_alloc_init;
    callbacks.args = writer;
    element_size = sizeof(SFBinlogWriterBuffer);
    if (use_fixed_buffer_size) {
        element_size += max_record_size;
        callbacks.destroy_func = NULL;
    } else {
        callbacks.destroy_func = binlog_wbuffer_destroy_func;
    }
    if ((result=fast_mblock_init_ex2(&thread->mblock, "binlog-wbuffer",
                     element_size, alloc_elements_once, 0,
                     &callbacks, true, NULL)) != 0)
    {
        return result;
    }

    if ((result=fc_queue_init(&thread->queue, (unsigned long)
                    (&((SFBinlogWriterBuffer *)NULL)->next))) != 0)
    {
        return result;
    }

    thread->flush_writers.head = thread->flush_writers.tail = NULL;
    return fc_create_thread(&tid, binlog_writer_func, thread,
            SF_G_THREAD_STACK_SIZE);
}

int sf_binlog_writer_change_order_by(SFBinlogWriterInfo *writer,
        const short order_by)
{
    SFBinlogWriterBuffer *buffer;

    if (writer->order_by == order_by) {
        return 0;
    }

    if (!(order_by == SF_BINLOG_WRITER_TYPE_ORDER_BY_NONE ||
                order_by == SF_BINLOG_WRITER_TYPE_ORDER_BY_VERSION))
    {
        logError("file: "__FILE__", line: %d, "
                "invalid order by: %d!", __LINE__, order_by);
        return EINVAL;
    }

    if (writer->thread->order_mode != SF_BINLOG_THREAD_ORDER_MODE_VARY) {
        logError("file: "__FILE__", line: %d, "
                "unexpected order mode: %d, can't set "
                "order by to %d!", __LINE__,
                writer->thread->order_mode, order_by);
        return EINVAL;
    }

    if (order_by == SF_BINLOG_WRITER_TYPE_ORDER_BY_VERSION) {
        if (writer->version_ctx.ring.slots == NULL) {
            logError("file: "__FILE__", line: %d, "
                    "the writer is NOT versioned writer, can't "
                    "set order by to %d!", __LINE__, order_by);
            return EINVAL;
        }
    }

    if ((buffer=sf_binlog_writer_alloc_versioned_buffer_ex(writer, order_by,
                    order_by, SF_BINLOG_BUFFER_TYPE_CHANGE_ORDER_TYPE)) == NULL)
    {
        return ENOMEM;
    }

    fc_queue_push(&writer->thread->queue, buffer);
    return 0;
}

static inline int sf_binlog_writer_push_directive(SFBinlogWriterInfo *writer,
        const int buffer_type, const int64_t version)
{
    SFBinlogWriterBuffer *buffer;

    if ((buffer=sf_binlog_writer_alloc_versioned_buffer_ex(writer,
                    version, version, buffer_type)) == NULL)
    {
        return ENOMEM;
    }

    fc_queue_push(&writer->thread->queue, buffer);
    return 0;
}

int sf_binlog_writer_change_next_version(SFBinlogWriterInfo *writer,
        const int64_t next_version)
{
    return sf_binlog_writer_push_directive(writer,
            SF_BINLOG_BUFFER_TYPE_SET_NEXT_VERSION,
            next_version);
}

int sf_binlog_writer_notify_exit(SFBinlogWriterInfo *writer)
{
    return sf_binlog_writer_push_directive(writer,
            SF_BINLOG_BUFFER_TYPE_NOTIFY_EXIT, 0);
}
