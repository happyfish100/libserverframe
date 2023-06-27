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

//sf_binlog_writer.h

#ifndef _SF_BINLOG_WRITER_H_
#define _SF_BINLOG_WRITER_H_

#include "fastcommon/fc_queue.h"
#include "fastcommon/fc_atomic.h"
#include "sf_types.h"
#include "sf_file_writer.h"

#define SF_BINLOG_THREAD_ORDER_MODE_FIXED       0
#define SF_BINLOG_THREAD_ORDER_MODE_VARY        1

#define SF_BINLOG_WRITER_TYPE_ORDER_BY_NONE     0
#define SF_BINLOG_WRITER_TYPE_ORDER_BY_VERSION  1

#define SF_BINLOG_BUFFER_TYPE_WRITE_TO_FILE        0  //default type, must be 0
#define SF_BINLOG_BUFFER_TYPE_SET_NEXT_VERSION     1
#define SF_BINLOG_BUFFER_TYPE_CHANGE_ORDER_TYPE    2
#define SF_BINLOG_BUFFER_TYPE_CHANGE_PASSIVE_WRITE 3
#define SF_BINLOG_BUFFER_TYPE_CHANGE_CALL_FSYNC    4
#define SF_BINLOG_BUFFER_TYPE_SET_WRITE_INDEX      5
#define SF_BINLOG_BUFFER_TYPE_ROTATE_FILE          6
#define SF_BINLOG_BUFFER_TYPE_NOTIFY_EXIT          7
#define SF_BINLOG_BUFFER_TYPE_FLUSH_FILE           8

#define SF_BINLOG_BUFFER_SET_VERSION(buffer, ver)  \
    (buffer)->version.first = (buffer)->version.last = ver

struct sf_binlog_writer_info;

typedef struct sf_binlog_writer_buffer {
    SFVersionRange version;
    BufferInfo bf;
    int type;
    uint32_t timestamp;  //for flow ctrol
    struct sf_binlog_writer_info *writer;
    struct sf_binlog_writer_buffer *next;
} SFBinlogWriterBuffer;

typedef struct sf_binlog_writer_slot {
    SFBinlogWriterBuffer head;
} SFBinlogWriterSlot;

typedef struct sf_binlog_writer_buffer_ring {
    SFBinlogWriterSlot *slots;
    int waiting_count;
    int max_waitings;
    int size;
} SFBinlogWriterBufferRing;

typedef struct binlog_writer_thread {
    struct fast_mblock_man mblock;
    struct fc_queue queue;
    char name[64];
    volatile bool running;
    bool use_fixed_buffer_size;
    bool passive_write;
    char order_mode;
    struct {
        int max_delay;  //in seconds
        volatile uint32_t last_timestamp;
        int waiting_count;
        pthread_lock_cond_pair_t lcp;
    } flow_ctrol;
    struct {
        struct sf_binlog_writer_info *head;
        struct sf_binlog_writer_info *tail;
    } flush_writers;
} SFBinlogWriterThread;

typedef struct sf_binlog_writer_info {
    SFFileWriterInfo fw;

    struct {
        SFBinlogWriterBufferRing ring;
        int64_t next;
        int64_t change_count;  //version change count
    } version_ctx;
    SFBinlogWriterThread *thread;

    short order_by;
    struct {
        bool in_queue;
        struct sf_binlog_writer_info *next;
    } flush;
} SFBinlogWriterInfo;

typedef struct sf_binlog_writer_context {
    SFBinlogWriterInfo writer;
    SFBinlogWriterThread thread;
} SFBinlogWriterContext;

#ifdef __cplusplus
extern "C" {
#endif

int sf_binlog_writer_init_normal_ex(SFBinlogWriterInfo *writer,
        const char *data_path, const char *subdir_name,
        const char *file_prefix, const int buffer_size,
        const int64_t file_rotate_size);

int sf_binlog_writer_init_by_version_ex(SFBinlogWriterInfo *writer,
        const char *data_path, const char *subdir_name,
        const char *file_prefix, const uint64_t next_version,
        const int buffer_size, const int ring_size,
        const int64_t file_rotate_size);

int sf_binlog_writer_init_thread_ex(SFBinlogWriterThread *thread,
        const char *name, SFBinlogWriterInfo *writer, const short order_mode,
        const int max_delay, const int max_record_size, const bool
        use_fixed_buffer_size, const bool passive_write);

#define sf_binlog_writer_init_normal(writer,  \
        data_path, subdir_name, buffer_size)  \
    sf_binlog_writer_init_normal_ex(writer, data_path, subdir_name, \
            SF_BINLOG_FILE_PREFIX, buffer_size, SF_BINLOG_DEFAULT_ROTATE_SIZE)

#define sf_binlog_writer_init_by_version(writer, data_path,   \
        subdir_name, next_version, buffer_size, ring_size)    \
    sf_binlog_writer_init_by_version_ex(writer, data_path, subdir_name, \
            SF_BINLOG_FILE_PREFIX, next_version, buffer_size, \
            ring_size, SF_BINLOG_DEFAULT_ROTATE_SIZE)

#define sf_binlog_writer_init_thread(thread, name, \
        writer, max_delay, max_record_size) \
    sf_binlog_writer_init_thread_ex(thread, name, writer, \
            SF_BINLOG_THREAD_ORDER_MODE_FIXED, max_delay, \
            max_record_size, true, false)

static inline int sf_binlog_writer_init_ex(SFBinlogWriterContext *context,
        const char *data_path, const char *subdir_name,
        const char *file_prefix, const int buffer_size,
        const int max_delay, const int max_record_size)
{
    int result;
    if ((result=sf_binlog_writer_init_normal_ex(&context->writer,
                    data_path, subdir_name, file_prefix, buffer_size,
                    SF_BINLOG_DEFAULT_ROTATE_SIZE)) != 0)
    {
        return result;
    }

    return sf_binlog_writer_init_thread(&context->thread, subdir_name,
            &context->writer, max_delay, max_record_size);
}

#define sf_binlog_writer_init(context, data_path, subdir_name, \
        buffer_size, max_delay, max_record_size) \
    sf_binlog_writer_init_ex(context, data_path, subdir_name, \
            SF_BINLOG_FILE_PREFIX, buffer_size, max_delay, max_record_size)

void sf_binlog_writer_finish(SFBinlogWriterInfo *writer);

static inline void sf_binlog_writer_destroy_writer(
        SFBinlogWriterInfo *writer)
{
    sf_file_writer_destroy(&writer->fw);
    if (writer->version_ctx.ring.slots != NULL) {
        free(writer->version_ctx.ring.slots);
        writer->version_ctx.ring.slots = NULL;
    }
}

static inline void sf_binlog_writer_destroy_thread(
        SFBinlogWriterThread *thread)
{
    fast_mblock_destroy(&thread->mblock);
    fc_queue_destroy(&thread->queue);
}

static inline void sf_binlog_writer_destroy(
        SFBinlogWriterContext *context)
{
    sf_binlog_writer_finish(&context->writer);
    sf_binlog_writer_destroy_writer(&context->writer);
    sf_binlog_writer_destroy_thread(&context->thread);
}

int sf_binlog_writer_change_order_by(SFBinlogWriterInfo *writer,
        const short order_by);

int sf_binlog_writer_change_passive_write(SFBinlogWriterInfo *writer,
        const bool passive_write);

int sf_binlog_writer_change_call_fsync(SFBinlogWriterInfo *writer,
        const bool call_fsync);

int sf_binlog_writer_change_next_version(SFBinlogWriterInfo *writer,
        const int64_t next_version);

static inline int64_t sf_binlog_writer_get_next_version(
        SFBinlogWriterInfo *writer)
{
    return writer->version_ctx.next;
}

int sf_binlog_writer_rotate_file(SFBinlogWriterInfo *writer);

int sf_binlog_writer_flush_file(SFBinlogWriterInfo *writer);

int sf_binlog_writer_change_write_index(SFBinlogWriterInfo *writer,
        const int write_index);

int sf_binlog_writer_notify_exit(SFBinlogWriterInfo *writer);

#define sf_binlog_writer_set_flags(writer, flags) \
    sf_file_writer_set_flags(&(writer)->fw, flags)

#define sf_binlog_writer_get_last_version_ex(writer, log_level) \
    sf_file_writer_get_last_version_ex(&(writer)->fw, log_level)

#define sf_binlog_writer_get_last_version(writer) \
    sf_file_writer_get_last_version(&(writer)->fw)

#define sf_binlog_writer_get_last_version_silence(writer) \
    sf_file_writer_get_last_version_silence(&(writer)->fw)

#define sf_binlog_get_indexes(writer, start_index, last_index) \
    sf_file_writer_get_indexes(&(writer)->fw, start_index, last_index)

#define sf_binlog_get_start_index(writer) \
    sf_file_writer_get_start_index(&(writer)->fw)

#define sf_binlog_get_last_index(writer) \
    sf_file_writer_get_last_index(&(writer)->fw)

#define sf_binlog_get_current_write_index(writer) \
    sf_file_writer_get_current_write_index(&(writer)->fw)

#define sf_binlog_get_current_write_position(writer, position) \
    sf_file_writer_get_current_position(&(writer)->fw, position)

static inline SFBinlogWriterBuffer *sf_binlog_writer_alloc_buffer(
        SFBinlogWriterThread *thread)
{
    SFBinlogWriterBuffer *buffer;

    if ((buffer=fast_mblock_alloc_object(&thread->mblock)) != NULL) {
        buffer->type = SF_BINLOG_BUFFER_TYPE_WRITE_TO_FILE;
    }
    return buffer;
}

#define sf_binlog_writer_alloc_one_version_buffer(writer, version) \
    sf_binlog_writer_alloc_versioned_buffer_ex(writer, version, \
            version, SF_BINLOG_BUFFER_TYPE_WRITE_TO_FILE)

#define sf_binlog_writer_alloc_multi_version_buffer(writer, \
        first_version, last_version) \
    sf_binlog_writer_alloc_versioned_buffer_ex(writer, first_version, \
            last_version, SF_BINLOG_BUFFER_TYPE_WRITE_TO_FILE)

static inline SFBinlogWriterBuffer *sf_binlog_writer_alloc_versioned_buffer_ex(
        SFBinlogWriterInfo *writer, const int64_t first_version,
        const int64_t last_version, const int type)
{
    SFBinlogWriterBuffer *buffer;

    buffer = (SFBinlogWriterBuffer *)fast_mblock_alloc_object(
            &writer->thread->mblock);
    if (buffer != NULL) {
        buffer->type = type;
        buffer->writer = writer;
        buffer->version.first = first_version;
        buffer->version.last = last_version;
    }
    return buffer;
}

#define sf_binlog_writer_get_filepath(data_path, subdir_name, filepath, size) \
    sf_file_writer_get_filepath(data_path, subdir_name, filepath, size)

#define sf_binlog_writer_get_filename_ex(data_path, subdir_name, \
        file_prefix, binlog_index, filename, size) \
        sf_file_writer_get_filename_ex(data_path, subdir_name, \
                file_prefix, binlog_index, filename, size)

#define sf_binlog_writer_get_filename(data_path, \
        subdir_name, binlog_index, filename, size) \
        sf_file_writer_get_filename(data_path, subdir_name, \
                binlog_index, filename, size)

#define sf_binlog_writer_get_index_filename(data_path, \
        subdir_name, filename, size) \
        sf_file_writer_get_index_filename(data_path, \
                subdir_name, filename, size)

#define sf_binlog_writer_get_binlog_indexes(data_path, \
        subdir_name, start_index, last_index) \
        sf_file_writer_get_binlog_indexes(data_path, \
                subdir_name, start_index, last_index)

#define sf_binlog_writer_get_binlog_start_index(data_path, \
        subdir_name, start_index) \
        sf_file_writer_get_binlog_start_index(data_path, \
                subdir_name, start_index)

#define sf_binlog_writer_get_binlog_last_index(data_path, \
        subdir_name, last_index) \
        sf_file_writer_get_binlog_last_index(data_path, \
                subdir_name, last_index)

#define sf_binlog_set_indexes(writer, start_index, last_index) \
    sf_file_writer_set_indexes(&(writer)->fw, start_index, last_index)

#define sf_binlog_writer_set_binlog_start_index(writer, start_index) \
    sf_file_writer_set_binlog_start_index(&(writer)->fw, start_index)

#define sf_binlog_writer_set_binlog_write_index(writer, last_index) \
    sf_file_writer_set_binlog_write_index(&(writer)->fw, last_index)

static inline void sf_push_to_binlog_write_queue(SFBinlogWriterInfo *writer,
        SFBinlogWriterBuffer *buffer)
{
    int64_t last_timestamp;

    last_timestamp = FC_ATOMIC_GET(writer->thread->flow_ctrol.last_timestamp);
    if (last_timestamp > 0 && g_current_time - last_timestamp >
            writer->thread->flow_ctrol.max_delay)
    {
        time_t start_time;
        int time_used;

        start_time = g_current_time;
        PTHREAD_MUTEX_LOCK(&writer->thread->flow_ctrol.lcp.lock);
        writer->thread->flow_ctrol.waiting_count++;
        last_timestamp = FC_ATOMIC_GET(writer->thread->
                flow_ctrol.last_timestamp);
        while (last_timestamp > 0 && g_current_time - last_timestamp >
                writer->thread->flow_ctrol.max_delay)
        {
            pthread_cond_wait(&writer->thread->flow_ctrol.lcp.cond,
                    &writer->thread->flow_ctrol.lcp.lock);
            last_timestamp = FC_ATOMIC_GET(writer->thread->
                    flow_ctrol.last_timestamp);
        }
        writer->thread->flow_ctrol.waiting_count--;
        PTHREAD_MUTEX_UNLOCK(&writer->thread->flow_ctrol.lcp.lock);

        time_used = g_current_time - start_time;
        if (time_used > 0) {
            logWarning("file: "__FILE__", line: %d, "
                    "subdir_name: %s, max_delay: %d s, flow ctrol waiting "
                    "time: %d s", __LINE__, writer->fw.cfg.subdir_name,
                    writer->thread->flow_ctrol.max_delay, time_used);
        }
    }

    buffer->timestamp = g_current_time;
    fc_queue_push(&writer->thread->queue, buffer);
}

#define sf_binlog_writer_get_last_lines(data_path, subdir_name, \
        current_write_index, buff, buff_size, count, length)  \
        sf_file_writer_get_last_lines(data_path, subdir_name, \
                current_write_index, buff, buff_size, count, length)

#ifdef __cplusplus
}
#endif

#endif
