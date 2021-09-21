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

//sf_ordered_writer.h

#ifndef _SF_ORDERED_WRITER_H_
#define _SF_ORDERED_WRITER_H_

#include "fastcommon/sorted_queue.h"
#include "sf_file_writer.h"

typedef struct sf_writer_version_info {
    int64_t version;
    struct sf_writer_version_info *next;
} SFWriterVersionInfo;

typedef struct sf_ordered_writer_buffer {
    int64_t version;
    BufferInfo bf;
    struct sf_ordered_writer_buffer *next;
} SFOrderedWriterBuffer;

typedef struct sf_orderd_writer_thread {
    struct {
        struct fast_mblock_man version;
        struct fast_mblock_man buffer;
    } allocators;

    struct {
        struct fc_queue version;
        struct sorted_queue buffer;
    } queues;
    char name[64];
    volatile bool running;
} SFOrderedWriterThread;

typedef struct sf_ordered_writer_info {
    SFFileWriterInfo fw;
    SFBinlogBuffer binlog_buffer;
    SFOrderedWriterThread *thread;
} SFOrderedWriterInfo;

typedef struct sf_ordered_writer_context {
    SFOrderedWriterInfo writer;
    SFOrderedWriterThread thread;
} SFOrderedWriterContext;

#ifdef __cplusplus
extern "C" {
#endif

int sf_ordered_writer_init(SFOrderedWriterContext *context,
        const char *data_path, const char *subdir_name,
        const int buffer_size, const int max_record_size);

#define sf_ordered_writer_set_flags(writer, flags) \
    sf_file_writer_set_flags(&(writer)->fw, flags)

#define sf_ordered_writer_get_last_version(writer) \
    sf_ordered_writer_get_last_version(&(writer)->fw)

void sf_ordered_writer_finish(SFOrderedWriterInfo *writer);

#define sf_ordered_writer_get_current_index(writer) \
    sf_file_writer_get_current_index(&(writer)->fw)

#define sf_ordered_writer_get_current_position(writer, position) \
    sf_file_writer_get_current_position(&(writer)->fw, position)

static inline SFOrderedWriterBuffer *sf_ordered_writer_alloc_buffer(
        SFOrderedWriterThread *thread)
{
    return (SFOrderedWriterBuffer *)fast_mblock_alloc_object(
            &thread->allocators.buffer);
}

static inline SFOrderedWriterBuffer *sf_ordered_writer_alloc_versioned_buffer_ex(
        SFOrderedWriterInfo *writer, const int64_t version)
{
    SFOrderedWriterBuffer *buffer;
    buffer = (SFOrderedWriterBuffer *)fast_mblock_alloc_object(
            &writer->thread->allocators.buffer);
    if (buffer != NULL) {
        buffer->version = version;
    }
    return buffer;
}

#define sf_ordered_writer_get_filepath(data_path, subdir_name, filename, size) \
    sf_file_writer_get_filepath(data_path, subdir_name, filename, size)

#define sf_ordered_writer_get_filename(data_path,  \
        subdir_name, binlog_index, filename, size) \
        sf_file_writer_get_filename(data_path, subdir_name, \
                binlog_index, filename, size)

#define sf_ordered_writer_set_binlog_index(writer, binlog_index) \
    sf_file_writer_set_binlog_index(&(writer)->fw, binlog_index)

#define sf_push_to_binlog_thread_queue(thread, buffer) \
    sorted_queue_push(&(thread)->queues.buffer, buffer)

static inline void sf_push_to_binlog_write_queue(SFOrderedWriterInfo *writer,
        SFOrderedWriterBuffer *buffer)
{
    sorted_queue_push(&writer->thread->queues.buffer, buffer);
}

#ifdef __cplusplus
}
#endif

#endif
