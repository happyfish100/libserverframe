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

#define SF_BINLOG_SUBDIR_NAME_SIZE 128
#define SF_BINLOG_FILE_MAX_SIZE   (1024 * 1024 * 1024)  //for binlog rotating by size
#define SF_BINLOG_FILE_PREFIX     "binlog"
#define SF_BINLOG_FILE_EXT_FMT    ".%06d"

#define SF_BINLOG_BUFFER_LENGTH(buffer) ((buffer).end - (buffer).buff)
#define SF_BINLOG_BUFFER_REMAIN(buffer) ((buffer).end - (buffer).current)

typedef struct sf_file_writer_info {
    struct {
        const char *data_path;
        char subdir_name[SF_BINLOG_SUBDIR_NAME_SIZE];
        int max_record_size;
    } cfg;

    struct {
        int index;   //current write index
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
} SFFileWriterInfo;

#ifdef __cplusplus
extern "C" {
#endif

int sf_file_writer_init(SFFileWriterInfo *writer,
        const char *data_path, const char *subdir_name,
        const int buffer_size);

void sf_file_writer_destroy(SFFileWriterInfo *writer);

int sf_file_writer_deal_versioned_buffer(SFFileWriterInfo *writer,
        BufferInfo *buffer, const int64_t version);

#define sf_file_writer_deal_buffer(writer, buffer) \
    sf_file_writer_deal_versioned_buffer(writer, buffer, 0)

int sf_file_writer_flush(SFFileWriterInfo *writer);

static inline void sf_file_writer_set_flags(
        SFFileWriterInfo *writer, const short flags)
{
    writer->flags = flags;
}

static inline int64_t sf_file_writer_get_last_version(
        SFFileWriterInfo *writer)
{
    if (writer->flags & SF_FILE_WRITER_FLAGS_WANT_DONE_VERSION) {
        return writer->last_versions.done;
    } else {
        logError("file: "__FILE__", line: %d, "
                "should set writer flags to %d!", __LINE__,
                SF_FILE_WRITER_FLAGS_WANT_DONE_VERSION);
        return -1;
    }
}

int sf_file_writer_get_binlog_index(const char *data_path,
        const char *subdir_name, int *write_index);

int sf_file_writer_get_current_index(SFFileWriterInfo *writer);

static inline void sf_file_writer_get_current_position(
        SFFileWriterInfo *writer, SFBinlogFilePosition *position)
{
    position->index = writer->binlog.index;
    position->offset = writer->file.size;
}

static inline const char *sf_file_writer_get_filepath(
        const char *data_path, const char *subdir_name,
        char *filename, const int size)
{
    snprintf(filename, size, "%s/%s", data_path, subdir_name);
    return filename;
}

static inline const char *sf_file_writer_get_filename(
        const char *data_path, const char *subdir_name,
        const int binlog_index, char *filename, const int size)
{
    snprintf(filename, size, "%s/%s/%s"SF_BINLOG_FILE_EXT_FMT, data_path,
            subdir_name, SF_BINLOG_FILE_PREFIX, binlog_index);
    return filename;
}

const char *sf_file_writer_get_index_filename(const char *data_path,
        const char *subdir_name, char *filename, const int size);

int sf_file_writer_set_binlog_index(SFFileWriterInfo *writer,
        const int binlog_index);

int sf_file_writer_get_last_lines(const char *data_path,
        const char *subdir_name, const int current_write_index,
        char *buff, const int buff_size, int *count, int *length);

#ifdef __cplusplus
}
#endif

#endif
