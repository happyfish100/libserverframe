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

//sf_file_writer.h

#ifndef _SF_FILE_WRITER_H_
#define _SF_FILE_WRITER_H_

#include "fastcommon/fc_queue.h"
#include "sf_types.h"

#define SF_FILE_WRITER_FLAGS_WANT_DONE_VERSION  1

#define SF_BINLOG_SUBDIR_NAME_SIZE     128
#define SF_BINLOG_FILE_PREFIX_SIZE      64
#define SF_BINLOG_DEFAULT_ROTATE_SIZE  (1024 * 1024 * 1024)
#define SF_BINLOG_NEVER_ROTATE_FILE    0
#define SF_BINLOG_FILE_PREFIX          "binlog"
#define SF_BINLOG_FILE_EXT_FMT         ".%06d"

struct sf_file_writer_info;

typedef void (*sf_file_write_done_callback)(
        struct sf_file_writer_info *writer, void *args);

typedef struct sf_file_writer_info {
    struct {
        const char *data_path;
        char subdir_name[SF_BINLOG_SUBDIR_NAME_SIZE];
        char file_prefix[SF_BINLOG_FILE_PREFIX_SIZE];
        int64_t file_rotate_size;
        int max_record_size;
        bool call_fsync;
    } cfg;

    struct {
        int start_index;  //for read only
        int last_index;   //for write
        int compress_index;
    } binlog;

    struct {
        int fd;
        int64_t size;
        char *name;
    } file;

    int64_t total_count;
    SFBinlogBuffer binlog_buffer;

    short flags;
    struct {
        int64_t pending;
        volatile int64_t done;
    } last_versions;

    struct {
        sf_file_write_done_callback func;
        void *args;
    } write_done_callback;

} SFFileWriterInfo;

#ifdef __cplusplus
extern "C" {
#endif

int sf_file_writer_init(SFFileWriterInfo *writer, const char *data_path,
        const char *subdir_name, const char *file_prefix,
        const int max_record_size, const int buffer_size,
        const int64_t file_rotate_size, const bool call_fsync);

void sf_file_writer_destroy(SFFileWriterInfo *writer);

int sf_file_writer_deal_versioned_buffer(SFFileWriterInfo *writer,
        BufferInfo *buffer, const int64_t version);

#define sf_file_writer_deal_buffer(writer, buffer) \
    sf_file_writer_deal_versioned_buffer(writer, buffer, 0)

int sf_file_writer_flush(SFFileWriterInfo *writer);

int sf_file_writer_fsync(SFFileWriterInfo *writer);

#define SF_FILE_WRITER_DATA_END_BUFF(writer) (writer)->binlog_buffer.data_end
#define SF_FILE_WRITER_CURRENT_DATA_VERSION(writer) \
    (writer)->last_versions.pending
#define SF_FILE_WRITER_NEXT_DATA_VERSION(writer) \
    ++((writer)->last_versions.pending)

int sf_file_writer_save_buffer_ex(SFFileWriterInfo *writer,
        const int length, const bool flush);

static inline int sf_file_writer_save_buffer(
        SFFileWriterInfo *writer, const int length)
{
    const bool flush = false;
    return sf_file_writer_save_buffer_ex(writer, length, flush);
}

static inline int sf_file_writer_flush_buffer(
        SFFileWriterInfo *writer, const int length)
{
    const bool flush = true;
    return sf_file_writer_save_buffer_ex(writer, length, flush);
}

static inline void sf_file_writer_set_flags(
        SFFileWriterInfo *writer, const short flags)
{
    writer->flags = flags;
}

static inline void sf_file_writer_set_call_fsync(
        SFFileWriterInfo *writer, const bool call_fsync)
{
    writer->cfg.call_fsync = call_fsync;
}

static inline void sf_file_writer_set_write_done_callback (
        SFFileWriterInfo *writer, sf_file_write_done_callback callback,
        void *args)
{
    writer->write_done_callback.func = callback;
    writer->write_done_callback.args = args;
}

static inline int64_t sf_file_writer_get_last_version_ex(
        SFFileWriterInfo *writer, const int log_level)
{
    if (writer->flags & SF_FILE_WRITER_FLAGS_WANT_DONE_VERSION) {
        return writer->last_versions.done;
    } else {
        if (FC_LOG_BY_LEVEL(log_level)) {
            log_it_ex(&g_log_context, log_level, "file: %s, line: %d, "
                    "writer: %s, should set writer flags to %d!",
                    __FILE__, __LINE__, writer->cfg.subdir_name,
                    SF_FILE_WRITER_FLAGS_WANT_DONE_VERSION);
        }

        return -1;
    }
}

#define sf_file_writer_get_last_version(writer) \
    sf_file_writer_get_last_version_ex(writer, LOG_ERR)

#define sf_file_writer_get_last_version_silence(writer) \
    sf_file_writer_get_last_version_ex(writer, LOG_NOTHING)

int sf_file_writer_get_binlog_indexes(const char *data_path,
        const char *subdir_name, int *start_index, int *last_index);

static inline int sf_file_writer_get_binlog_start_index(
        const char *data_path, const char *subdir_name,
        int *start_index)
{
    int last_index;
    return sf_file_writer_get_binlog_indexes(data_path,
            subdir_name, start_index, &last_index);
}

static inline int sf_file_writer_get_binlog_last_index(
        const char *data_path, const char *subdir_name,
        int *last_index)
{
    int start_index;
    return sf_file_writer_get_binlog_indexes(data_path,
            subdir_name, &start_index, last_index);
}

int sf_file_writer_set_indexes(SFFileWriterInfo *writer,
        const int start_index, const int last_index);

int sf_file_writer_get_indexes(SFFileWriterInfo *writer,
        int *start_index, int *last_index);

static inline int sf_file_writer_get_start_index(SFFileWriterInfo *writer)
{
    int start_index;
    int last_index;

    sf_file_writer_get_indexes(writer, &start_index, &last_index);
    return start_index;
}

static inline int sf_file_writer_get_last_index(SFFileWriterInfo *writer)
{
    int start_index;
    int last_index;

    sf_file_writer_get_indexes(writer, &start_index, &last_index);
    return last_index;
}

#define sf_file_writer_get_current_write_index(writer) \
    sf_file_writer_get_last_index(writer)

static inline void sf_file_writer_get_current_position(
        SFFileWriterInfo *writer, SFBinlogFilePosition *position)
{
    position->index = writer->binlog.last_index;
    position->offset = writer->file.size;
}

static inline const char *sf_file_writer_get_filepath(
        const char *data_path, const char *subdir_name,
        char *filepath, const int size)
{
    snprintf(filepath, size, "%s/%s", data_path, subdir_name);
    return filepath;
}

static inline const char *sf_file_writer_get_filename_ex(
        const char *data_path, const char *subdir_name,
        const char *file_prefix, const int binlog_index,
        char *filename, const int size)
{
    snprintf(filename, size, "%s/%s/%s"SF_BINLOG_FILE_EXT_FMT,
            data_path, subdir_name, file_prefix, binlog_index);
    return filename;
}

#define sf_file_writer_get_filename(data_path, subdir_name, \
        binlog_index, filename, size) \
    sf_file_writer_get_filename_ex(data_path, subdir_name, \
        SF_BINLOG_FILE_PREFIX, binlog_index, filename, size)

const char *sf_file_writer_get_index_filename(const char *data_path,
        const char *subdir_name, char *filename, const int size);

int sf_file_writer_set_binlog_start_index(SFFileWriterInfo *writer,
        const int start_index);

int sf_file_writer_set_binlog_write_index(SFFileWriterInfo *writer,
        const int last_index);

int sf_file_writer_get_last_lines(const char *data_path,
        const char *subdir_name, const int current_write_index,
        char *buff, const int buff_size, int *count, int *length);

int sf_file_writer_write_to_binlog_index_file_ex(const char *data_path,
        const char *subdir_name, const char *file_prefix,
        const int start_index, const int last_index,
        const int compress_index);

#define sf_file_writer_write_to_binlog_index_file(data_path,  \
        subdir_name, start_index, last_index) \
    sf_file_writer_write_to_binlog_index_file_ex(data_path, subdir_name, \
            SF_BINLOG_FILE_PREFIX, start_index, last_index, 0)

#ifdef __cplusplus
}
#endif

#endif
