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
#include "sf_types.h"
#include "sf_file_writer.h"

#define SF_BINLOG_THREAD_ORDER_MODE_FIXED       0
#define SF_BINLOG_THREAD_ORDER_MODE_VARY        1

#define SF_BINLOG_WRITER_TYPE_ORDER_BY_NONE     0
#define SF_BINLOG_WRITER_TYPE_ORDER_BY_VERSION  1

#define SF_BINLOG_BUFFER_TYPE_WRITE_TO_FILE     0  //default type, must be 0
#define SF_BINLOG_BUFFER_TYPE_SET_NEXT_VERSION  1
#define SF_BINLOG_BUFFER_TYPE_CHANGE_ORDER_TYPE 2
#define SF_BINLOG_BUFFER_TYPE_NOTIFY_EXIT       3

#define SF_BINLOG_BUFFER_SET_VERSION(buffer, ver)  \
    (buffer)->version.first = (buffer)->version.last = ver

struct sf_binlog_writer_info;

typedef struct sf_binlog_writer_buffer {
    SFVersionRange version;
    BufferInfo bf;
    int64_t tag;
    int type;    //for versioned writer
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
    short order_mode;
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

int sf_binlog_writer_init_normal(SFBinlogWriterInfo *writer,
        const char *data_path, const char *subdir_name,
        const int buffer_size);

int sf_binlog_writer_init_by_version(SFBinlogWriterInfo *writer,
        const char *data_path, const char *subdir_name,
        const uint64_t next_version, const int buffer_size,
        const int ring_size);

int sf_binlog_writer_init_thread_ex(SFBinlogWriterThread *thread,
        const char *name, SFBinlogWriterInfo *writer, const short order_mode,
        const int max_record_size, const int writer_count,
        const bool use_fixed_buffer_size);

#define sf_binlog_writer_init_thread(thread, name, writer, max_record_size) \
    sf_binlog_writer_init_thread_ex(thread, name, writer, \
            SF_BINLOG_THREAD_ORDER_MODE_FIXED,  \
            max_record_size, 1, true)

static inline int sf_binlog_writer_init(SFBinlogWriterContext *context,
        const char *data_path, const char *subdir_name,
        const int buffer_size, const int max_record_size)
{
    int result;
    if ((result=sf_binlog_writer_init_normal(&context->writer,
                    data_path, subdir_name, buffer_size)) != 0)
    {
        return result;
    }

    return sf_binlog_writer_init_thread(&context->thread,
            subdir_name, &context->writer, max_record_size);
}

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

int sf_binlog_writer_change_next_version(SFBinlogWriterInfo *writer,
        const int64_t next_version);

int sf_binlog_writer_notify_exit(SFBinlogWriterInfo *writer);

#define sf_binlog_writer_set_flags(writer, flags) \
    sf_file_writer_set_flags(&(writer)->fw, flags)

#define sf_binlog_writer_get_last_version(writer) \
    sf_file_writer_get_last_version(&(writer)->fw)

#define sf_binlog_get_current_write_index(writer) \
    sf_file_writer_get_current_index(&(writer)->fw)

#define sf_binlog_get_current_write_position(writer, position) \
    sf_file_writer_get_current_position(&(writer)->fw, position)

static inline SFBinlogWriterBuffer *sf_binlog_writer_alloc_buffer(
        SFBinlogWriterThread *thread)
{
    return (SFBinlogWriterBuffer *)fast_mblock_alloc_object(&thread->mblock);
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

#define sf_binlog_writer_get_filepath(data_path, subdir_name, filename, size) \
    sf_file_writer_get_filepath(data_path, subdir_name, filename, size)

#define sf_binlog_writer_get_filename(data_path, \
        subdir_name, binlog_index, filename, size) \
        sf_file_writer_get_filename(data_path, subdir_name, \
                binlog_index, filename, size)

#define sf_binlog_writer_get_index_filename(data_path, \
        subdir_name, filename, size) \
        sf_file_writer_get_index_filename(data_path, \
                subdir_name, filename, size)

#define sf_binlog_writer_get_binlog_index(data_path, \
        subdir_name, write_index) \
        sf_file_writer_get_binlog_index(data_path, \
                subdir_name, write_index)

#define sf_binlog_writer_set_binlog_index(writer, binlog_index) \
    sf_file_writer_set_binlog_index(&(writer)->fw, binlog_index)

#define sf_push_to_binlog_thread_queue(thread, buffer) \
    fc_queue_push(&(thread)->queue, buffer)

static inline void sf_push_to_binlog_write_queue(SFBinlogWriterInfo *writer,
        SFBinlogWriterBuffer *buffer)
{
    buffer->type = SF_BINLOG_BUFFER_TYPE_WRITE_TO_FILE;
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
