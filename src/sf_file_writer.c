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
#include "sf_file_writer.h"

#define BINLOG_INDEX_ITEM_START_INDEX       "start_index"
#define BINLOG_INDEX_ITEM_CURRENT_WRITE     "current_write"
#define BINLOG_INDEX_ITEM_CURRENT_COMPRESS  "current_compress"

#define GET_BINLOG_FILENAME(writer) \
    sprintf(writer->file.name, "%s/%s/%s"SF_BINLOG_FILE_EXT_FMT, \
            writer->cfg.data_path, writer->cfg.subdir_name, \
            writer->cfg.file_prefix, writer->binlog.last_index)

#define GET_BINLOG_INDEX_FILENAME_EX(data_path,    \
        subdir_name, file_prefix, filename, size)  \
    snprintf(filename, size, "%s/%s/%s_index.dat", \
            data_path, subdir_name, file_prefix)

const char *sf_file_writer_get_index_filename(const char *data_path,
        const char *subdir_name, char *filename, const int size)
{
    GET_BINLOG_INDEX_FILENAME_EX(data_path, subdir_name,
            SF_BINLOG_FILE_PREFIX, filename, size);
    return filename;
}

int sf_file_writer_write_to_binlog_index_file_ex(const char *data_path,
        const char *subdir_name, const char *file_prefix,
        const int start_index, const int last_index,
        const int compress_index)
{
    char filename[PATH_MAX];
    char buff[256];
    int result;
    int len;

    GET_BINLOG_INDEX_FILENAME_EX(data_path, subdir_name,
            file_prefix, filename, sizeof(filename));
    len = sprintf(buff, "%s=%d\n"
            "%s=%d\n"
            "%s=%d\n",
            BINLOG_INDEX_ITEM_START_INDEX, start_index,
            BINLOG_INDEX_ITEM_CURRENT_WRITE, last_index,
            BINLOG_INDEX_ITEM_CURRENT_COMPRESS, compress_index);
    if ((result=safeWriteToFile(filename, buff, len)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "write to file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, filename, result, STRERROR(result));
    }

    return result;
}

static inline int write_to_binlog_index_file(SFFileWriterInfo *writer)
{
    return sf_file_writer_write_to_binlog_index_file_ex(
            writer->cfg.data_path, writer->cfg.subdir_name,
            writer->cfg.file_prefix, writer->binlog.start_index,
            writer->binlog.last_index, writer->binlog.compress_index);
}

static int get_binlog_info_from_file(const char *data_path,
        const char *subdir_name, int *start_index,
        int *last_index, int *compress_index)
{
    char full_filename[PATH_MAX];
    IniContext ini_context;
    int result;

    GET_BINLOG_INDEX_FILENAME_EX(data_path,
            subdir_name, SF_BINLOG_FILE_PREFIX,
            full_filename, sizeof(full_filename));
    if (access(full_filename, F_OK) != 0) {
        return errno != 0 ? errno : EPERM;
    }

    if ((result=iniLoadFromFile(full_filename, &ini_context)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "load from file \"%s\" fail, error code: %d",
                __LINE__, full_filename, result);
        return result;
    }

    *start_index = iniGetIntValue(NULL,
            BINLOG_INDEX_ITEM_START_INDEX,
            &ini_context, 0);
    *last_index = iniGetIntValue(NULL,
            BINLOG_INDEX_ITEM_CURRENT_WRITE,
            &ini_context, 0);
    *compress_index = iniGetIntValue(NULL,
            BINLOG_INDEX_ITEM_CURRENT_COMPRESS,
            &ini_context, 0);

    iniFreeContext(&ini_context);
    return 0;
}

int sf_file_writer_get_binlog_indexes(const char *data_path,
        const char *subdir_name, int *start_index, int *last_index)
{
    int result;
    int compress_index;

    result = get_binlog_info_from_file(data_path, subdir_name,
            start_index, last_index, &compress_index);
    if (result == ENOENT) {
        *start_index = *last_index = 0;
        return 0;
    } else {
        return result;
    }
}

static inline int get_binlog_index_from_file(SFFileWriterInfo *writer)
{
    int result;

    result = get_binlog_info_from_file(writer->cfg.data_path,
            writer->cfg.subdir_name, &writer->binlog.start_index,
            &writer->binlog.last_index, &writer->binlog.compress_index);
    if (result == ENOENT) {
        writer->binlog.start_index = 0;
        writer->binlog.last_index = 0;
        writer->binlog.compress_index = 0;
        if (writer->cfg.file_rotate_size > 0) {
            return write_to_binlog_index_file(writer);
        } else {
            return 0;
        }
    } else {
        return result;
    }
}

static int open_writable_binlog(SFFileWriterInfo *writer)
{
    if (writer->file.fd >= 0) {
        close(writer->file.fd);
    }

    GET_BINLOG_FILENAME(writer);
    writer->file.fd = open(writer->file.name, O_WRONLY |
            O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (writer->file.fd < 0) {
        logError("file: "__FILE__", line: %d, "
                "open file \"%s\" fail, "
                "errno: %d, error info: %s",
                __LINE__, writer->file.name,
                errno, STRERROR(errno));
        return errno != 0 ? errno : EACCES;
    }

    writer->file.size = lseek(writer->file.fd, 0, SEEK_END);
    if (writer->file.size < 0) {
        logError("file: "__FILE__", line: %d, "
                "lseek file \"%s\" fail, "
                "errno: %d, error info: %s",
                __LINE__, writer->file.name,
                errno, STRERROR(errno));
        return errno != 0 ? errno : EIO;
    }

    return 0;
}

static int open_next_binlog(SFFileWriterInfo *writer)
{
    GET_BINLOG_FILENAME(writer);
    if (access(writer->file.name, F_OK) == 0) {
        char bak_filename[PATH_MAX];
        char date_str[32];

        snprintf(bak_filename, sizeof(bak_filename), "%s.%s",
                writer->file.name, formatDatetime(g_current_time,
                    "%Y%m%d%H%M%S", date_str, sizeof(date_str)));
        if (rename(writer->file.name, bak_filename) == 0) {
            logWarning("file: "__FILE__", line: %d, "
                    "binlog file %s exist, rename to %s",
                    __LINE__, writer->file.name, bak_filename);
        } else {
            logError("file: "__FILE__", line: %d, "
                    "rename binlog %s to backup %s fail, "
                    "errno: %d, error info: %s",
                    __LINE__, writer->file.name, bak_filename,
                    errno, STRERROR(errno));
            return errno != 0 ? errno : EPERM;
        }
    }

    return open_writable_binlog(writer);
}

static int do_write_to_file(SFFileWriterInfo *writer,
        char *buff, const int len)
{
    int result;

    if (fc_safe_write(writer->file.fd, buff, len) != len) {
        result = errno != 0 ? errno : EIO;
        logError("file: "__FILE__", line: %d, "
                "write to binlog file \"%s\" fail, "
                "errno: %d, error info: %s",
                __LINE__, writer->file.name,
                result, STRERROR(result));
        return result;
    }

    if (writer->cfg.call_fsync) {
        if (fsync(writer->file.fd) != 0) {
            result = errno != 0 ? errno : EIO;
            logError("file: "__FILE__", line: %d, "
                    "fsync to binlog file \"%s\" fail, errno: %d, "
                    "error info: %s", __LINE__, writer->file.name,
                    result, STRERROR(result));
            return result;
        }
    }

    writer->file.size += len;
    if (writer->write_done_callback.func != NULL) {
        writer->write_done_callback.func(writer,
                writer->write_done_callback.args);
    }

    return 0;
}

static int check_write_to_file(SFFileWriterInfo *writer,
        char *buff, const int len)
{
    int result;

    if ((writer->cfg.file_rotate_size <= 0) || (writer->file.size
                + len <= writer->cfg.file_rotate_size))
    {
        return do_write_to_file(writer, buff, len);
    }

    writer->binlog.last_index++;  //binlog rotate
    if ((result=write_to_binlog_index_file(writer)) == 0) {
        result = open_next_binlog(writer);
    }

    if (result != 0) {
        logError("file: "__FILE__", line: %d, "
                "open binlog file \"%s\" fail",
                __LINE__, writer->file.name);
        return result;
    }

    return do_write_to_file(writer, buff, len);
}

int sf_file_writer_flush(SFFileWriterInfo *writer)
{
    int result;
    int len;

    len = SF_BINLOG_BUFFER_PRODUCER_DATA_LENGTH(writer->binlog_buffer);
    if (len == 0) {
        return 0;
    }

    if ((result=check_write_to_file(writer, writer->
                    binlog_buffer.buff, len)) == 0)
    {
        if (writer->flags & SF_FILE_WRITER_FLAGS_WANT_DONE_VERSION) {
            writer->last_versions.done = writer->last_versions.pending;
        }
    }

    writer->binlog_buffer.data_end = writer->binlog_buffer.buff;
    return result;
}

int sf_file_writer_fsync(SFFileWriterInfo *writer)
{
    int result;

    if ((result=sf_file_writer_flush(writer)) != 0) {
        return result;
    }

    if (fsync(writer->file.fd) == 0) {
        return 0;
    } else {
        result = errno != 0 ? errno : EIO;
        logError("file: "__FILE__", line: %d, "
                "fsync to binlog file \"%s\" fail, errno: %d, "
                "error info: %s", __LINE__, writer->file.name,
                result, STRERROR(result));
        return result;
    }
}

int sf_file_writer_get_indexes(SFFileWriterInfo *writer,
        int *start_index, int *last_index)
{
    int result;

    if (writer == NULL) {   //for data recovery
        *start_index = *last_index = 0;
        return 0;
    }

    if (writer->binlog.last_index < 0) {
        if ((result=get_binlog_index_from_file(writer)) != 0) {
            *start_index = *last_index = -1;
            return result;
        }
    }

    *start_index = writer->binlog.start_index;
    *last_index = writer->binlog.last_index;
    return 0;
}

int sf_file_writer_deal_versioned_buffer(SFFileWriterInfo *writer,
        BufferInfo *buffer, const int64_t version)
{
    int result;

    if (buffer->length >= writer->binlog_buffer.size / 4) {
        if (SF_BINLOG_BUFFER_PRODUCER_DATA_LENGTH(writer->binlog_buffer) > 0) {
            if ((result=sf_file_writer_flush(writer)) != 0) {
                return result;
            }
        }

        if ((result=check_write_to_file(writer, buffer->buff,
                        buffer->length)) == 0)
        {
            if (writer->flags & SF_FILE_WRITER_FLAGS_WANT_DONE_VERSION) {
                writer->last_versions.pending = version;
                writer->last_versions.done = version;
            }
        }
        return result;
    }

    if (writer->cfg.file_rotate_size > 0 && writer->file.size +
            SF_BINLOG_BUFFER_PRODUCER_DATA_LENGTH(writer->binlog_buffer) +
            buffer->length > writer->cfg.file_rotate_size)
    {
        if ((result=sf_file_writer_flush(writer)) != 0) {
            return result;
        }
    } else if (SF_BINLOG_BUFFER_PRODUCER_BUFF_REMAIN(
                writer->binlog_buffer) < buffer->length)
    {
        if ((result=sf_file_writer_flush(writer)) != 0) {
            return result;
        }
    }

    if (writer->flags & SF_FILE_WRITER_FLAGS_WANT_DONE_VERSION) {
        writer->last_versions.pending = version;
    }
    memcpy(writer->binlog_buffer.data_end, buffer->buff, buffer->length);
    writer->binlog_buffer.data_end += buffer->length;

    return 0;
}

int sf_file_writer_save_buffer_ex(SFFileWriterInfo *writer,
        const int length, const bool flush)
{
    int result;

    if (writer->cfg.file_rotate_size > 0 && writer->file.size +
            SF_BINLOG_BUFFER_PRODUCER_DATA_LENGTH(writer->binlog_buffer) +
            length > writer->cfg.file_rotate_size)
    {
        if ((result=sf_file_writer_flush(writer)) != 0) {
            return result;
        }
    }

    writer->binlog_buffer.data_end += length;
    if (flush || SF_BINLOG_BUFFER_PRODUCER_BUFF_REMAIN(writer->
                binlog_buffer) < writer->cfg.max_record_size)
    {
        return sf_file_writer_flush(writer);
    } else {
        return 0;
    }
}

int sf_file_writer_init(SFFileWriterInfo *writer, const char *data_path,
        const char *subdir_name, const char *file_prefix,
        const int max_record_size, const int buffer_size,
        const int64_t file_rotate_size, const bool call_fsync)
{
    int result;
    int path_len;
    bool create;
    char filepath[PATH_MAX];

    writer->total_count = 0;
    writer->last_versions.pending = 0;
    writer->last_versions.done = 0;
    writer->flags = 0;
    sf_file_writer_set_write_done_callback(writer, NULL, NULL);
    if ((result=sf_binlog_buffer_init(&writer->
                    binlog_buffer, buffer_size)) != 0)
    {
        return result;
    }

    writer->cfg.max_record_size = max_record_size;
    writer->cfg.call_fsync = call_fsync;
    writer->cfg.file_rotate_size = file_rotate_size;
    writer->cfg.data_path = data_path;
    path_len = snprintf(filepath, sizeof(filepath),
            "%s/%s", data_path, subdir_name);
    if ((result=fc_check_mkdir_ex(filepath, 0775, &create)) != 0) {
        return result;
    }
    if (create) {
        SF_CHOWN_TO_RUNBY_RETURN_ON_ERROR(filepath);
    }

    writer->file.fd = -1;
    snprintf(writer->cfg.subdir_name,
            sizeof(writer->cfg.subdir_name),
            "%s", subdir_name);
    snprintf(writer->cfg.file_prefix,
            sizeof(writer->cfg.file_prefix),
            "%s", file_prefix);
    writer->file.name = (char *)fc_malloc(path_len + 32);
    if (writer->file.name == NULL) {
        return ENOMEM;
    }

    if ((result=get_binlog_index_from_file(writer)) != 0) {
        return result;
    }

    if ((result=open_writable_binlog(writer)) != 0) {
        return result;
    }

    return 0;
}

void sf_file_writer_destroy(SFFileWriterInfo *writer)
{
    if (writer->file.fd >= 0) {
        close(writer->file.fd);
        writer->file.fd = -1;
    }
    if (writer->file.name != NULL) {
        free(writer->file.name);
        writer->file.name = NULL;
    }
    sf_binlog_buffer_destroy(&writer->binlog_buffer);
}

int sf_file_writer_set_indexes(SFFileWriterInfo *writer,
        const int start_index, const int last_index)
{
    int result;

    if (writer->binlog.start_index != start_index ||
            writer->binlog.last_index != last_index)
    {
        writer->binlog.start_index = start_index;
        writer->binlog.last_index = last_index;
        if ((result=write_to_binlog_index_file(writer)) != 0) {
            return result;
        }
    }

    return 0;
}

int sf_file_writer_set_binlog_start_index(SFFileWriterInfo *writer,
        const int start_index)
{
    int result;

    if (writer->binlog.start_index != start_index) {
        writer->binlog.start_index = start_index;
        if ((result=write_to_binlog_index_file(writer)) != 0) {
            return result;
        }
    }

    return 0;
}

int sf_file_writer_set_binlog_write_index(SFFileWriterInfo *writer,
        const int last_index)
{
    int result;

    if (writer->binlog.last_index != last_index) {
        writer->binlog.last_index = last_index;
        if ((result=write_to_binlog_index_file(writer)) != 0) {
            return result;
        }
    }

    return open_writable_binlog(writer);
}

int sf_file_writer_get_last_lines(const char *data_path,
        const char *subdir_name, const int current_write_index,
        char *buff, const int buff_size, int *count, int *length)
{
    int result;
    int target_count;
    int count1;
    char filename[PATH_MAX];
    string_t lines;

    target_count = *count;
    sf_file_writer_get_filename(data_path, subdir_name,
            current_write_index, filename, sizeof(filename));
    if (access(filename, F_OK) == 0) {
        if ((result=fc_get_last_lines(filename, buff, buff_size,
                        &lines, count)) != 0)
        {
            if (result != ENOENT) {
                return result;
            }
        }

        if (*count >= target_count || current_write_index == 0) {
            memmove(buff, lines.str, lines.len);
            *length = lines.len;
            return 0;
        }
    } else {
        result = errno != 0 ? errno : EPERM;
        if (result == ENOENT) {
            *count = 0;
            *length = 0;
            return 0;
        } else {
            logError("file: "__FILE__", line: %d, "
                    "stat file %s fail, errno: %d, error info: %s",
                    __LINE__, filename, result, STRERROR(result));
            *count = 0;
            *length = 0;
            return result;
        }
    }

    sf_file_writer_get_filename(data_path, subdir_name,
            current_write_index - 1, filename, sizeof(filename));
    if (access(filename, F_OK) != 0) {
        result = errno != 0 ? errno : EPERM;
        if (result == ENOENT) {
            memmove(buff, lines.str, lines.len);
            *length = lines.len;
            return 0;
        } else {
            logError("file: "__FILE__", line: %d, "
                    "stat file %s fail, errno: %d, error info: %s",
                    __LINE__, filename, result, STRERROR(result));
            *count = 0;
            *length = 0;
            return result;
        }
    }

    count1 = target_count - *count;
    if ((result=fc_get_last_lines(filename, buff,
                    buff_size, &lines, &count1)) != 0)
    {
        *count = 0;
        *length = 0;
        return result;
    }

    memmove(buff, lines.str, lines.len);
    *length = lines.len;
    if (*count == 0) {
        *count = count1;
    } else {
        sf_file_writer_get_filename(data_path, subdir_name,
                current_write_index, filename, sizeof(filename));
        if ((result=fc_get_first_lines(filename, buff + (*length),
                        buff_size - (*length), &lines, count)) != 0)
        {
            *count = 0;
            *length = 0;
            return result;
        }

        *count += count1;
        *length += lines.len;
    }

    return 0;
}

int sf_file_writer_get_last_line(const char *data_path,
        const char *subdir_name, char *buff,
        const int buff_size, int *length)
{
    int result;
    int last_index;
    int count = 1;

    if ((result=sf_file_writer_get_binlog_last_index(data_path,
                    subdir_name, &last_index)) != 0)
    {
        *length = 0;
        return result;
    }

    return sf_file_writer_get_last_lines(data_path, subdir_name,
            last_index, buff, buff_size, &count, length);
}
