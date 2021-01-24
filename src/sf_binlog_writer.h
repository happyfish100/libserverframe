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

#define SF_BINLOG_THREAD_ORDER_MODE_FIXED       0
#define SF_BINLOG_THREAD_ORDER_MODE_VARY        1

#define SF_BINLOG_THREAD_TYPE_ORDER_BY_NONE     0
#define SF_BINLOG_THREAD_TYPE_ORDER_BY_VERSION  1

#define SF_BINLOG_BUFFER_TYPE_WRITE_TO_FILE     0  //default type, must be 0
#define SF_BINLOG_BUFFER_TYPE_SET_NEXT_VERSION  1
#define SF_BINLOG_BUFFER_TYPE_CHANGE_ORDER_TYPE 2

#define SF_BINLOG_SUBDIR_NAME_SIZE 128
#define SF_BINLOG_FILE_MAX_SIZE   (1024 * 1024 * 1024)  //for binlog rotating by size
#define SF_BINLOG_FILE_PREFIX     "binlog"
#define SF_BINLOG_FILE_EXT_FMT    ".%06d"

#define SF_BINLOG_BUFFER_LENGTH(buffer) ((buffer).end - (buffer).buff)
#define SF_BINLOG_BUFFER_REMAIN(buffer) ((buffer).end - (buffer).current)

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
    bool running;
    bool use_fixed_buffer_size;
    short order_mode;
    short order_by;
    struct {
        struct sf_binlog_writer_info *head;
        struct sf_binlog_writer_info *tail;
    } flush_writers;
} SFBinlogWriterThread;

typedef struct sf_binlog_writer_info {
    struct {
        char subdir_name[SF_BINLOG_SUBDIR_NAME_SIZE];
        int max_record_size;
    } cfg;

    struct {
        int index;
        int compress_index;
    } binlog;

    struct {
        int fd;
        int64_t size;
        char *name;
    } file;

    int64_t total_count;
    struct {
        SFBinlogWriterBufferRing ring;
        int64_t next;
        int64_t change_count;  //version change count
    } version_ctx;
    SFBinlogBuffer binlog_buffer;
    SFBinlogWriterThread *thread;
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

    extern char *g_sf_binlog_data_path;

int sf_binlog_writer_init_normal(SFBinlogWriterInfo *writer,
        const char *subdir_name, const int buffer_size);

int sf_binlog_writer_init_by_version(SFBinlogWriterInfo *writer,
        const char *subdir_name, const uint64_t next_version,
        const int buffer_size, const int ring_size);

int sf_binlog_writer_init_thread_ex(SFBinlogWriterThread *thread,
        SFBinlogWriterInfo *writer, const short order_mode,
        const short order_by, const int max_record_size,
        const int writer_count, const bool use_fixed_buffer_size);

#define sf_binlog_writer_init_thread(thread, \
        writer, order_by, max_record_size)   \
    sf_binlog_writer_init_thread_ex(thread, writer, \
            SF_BINLOG_THREAD_ORDER_MODE_FIXED,      \
            order_by, max_record_size, 1, true)

static inline int sf_binlog_writer_init(SFBinlogWriterContext *context,
        const char *subdir_name, const int buffer_size,
        const int max_record_size)
{
    int result;
    if ((result=sf_binlog_writer_init_normal(&context->writer,
                    subdir_name, buffer_size)) != 0)
    {
        return result;
    }

    return sf_binlog_writer_init_thread(&context->thread, &context->writer,
            SF_BINLOG_THREAD_TYPE_ORDER_BY_NONE, max_record_size);
}

int sf_binlog_writer_change_order_by(SFBinlogWriterInfo *writer,
        const short order_by);

int sf_binlog_writer_change_next_version(SFBinlogWriterInfo *writer,
        const int64_t next_version);

void sf_binlog_writer_finish(SFBinlogWriterInfo *writer);

int sf_binlog_get_current_write_index(SFBinlogWriterInfo *writer);

void sf_binlog_get_current_write_position(SFBinlogWriterInfo *writer,
        SFBinlogFilePosition *position);

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

static inline const char *sf_binlog_writer_get_filepath(const char *subdir_name,
        char *filename, const int size)
{
    snprintf(filename, size, "%s/%s", g_sf_binlog_data_path, subdir_name);
    return filename;
}

static inline const char *sf_binlog_writer_get_filename(const char *subdir_name,
        const int binlog_index, char *filename, const int size)
{
    snprintf(filename, size, "%s/%s/%s"SF_BINLOG_FILE_EXT_FMT,
            g_sf_binlog_data_path, subdir_name,
            SF_BINLOG_FILE_PREFIX, binlog_index);
    return filename;
}

int sf_binlog_writer_set_binlog_index(SFBinlogWriterInfo *writer,
        const int binlog_index);

#define sf_push_to_binlog_thread_queue(thread, buffer) \
    fc_queue_push(&(thread)->queue, buffer)

static inline void sf_push_to_binlog_write_queue(SFBinlogWriterInfo *writer,
        SFBinlogWriterBuffer *buffer)
{
    buffer->type = SF_BINLOG_BUFFER_TYPE_WRITE_TO_FILE;
    fc_queue_push(&writer->thread->queue, buffer);
}

int sf_binlog_writer_get_last_lines(const char *subdir_name,
        const int current_write_index, char *buff,
        const int buff_size, int *count, int *length);

#ifdef __cplusplus
}
#endif

#endif
