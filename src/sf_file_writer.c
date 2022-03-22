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

#define BINLOG_INDEX_FILENAME  SF_BINLOG_FILE_PREFIX"_index.dat"

#define BINLOG_INDEX_ITEM_CURRENT_WRITE     "current_write"
#define BINLOG_INDEX_ITEM_CURRENT_COMPRESS  "current_compress"

#define GET_BINLOG_FILENAME(writer) \
    sprintf(writer->file.name, "%s/%s/%s"SF_BINLOG_FILE_EXT_FMT, \
            writer->cfg.data_path, writer->cfg.subdir_name, \
            SF_BINLOG_FILE_PREFIX, writer->binlog.index)

#define GET_BINLOG_INDEX_FILENAME_EX(data_path, subdir_name, filename, size) \
    snprintf(filename, size, "%s/%s/%s", data_path, \
            subdir_name, BINLOG_INDEX_FILENAME)

#define GET_BINLOG_INDEX_FILENAME(writer, filename, size) \
    GET_BINLOG_INDEX_FILENAME_EX(writer->cfg.data_path,   \
            writer->cfg.subdir_name, filename, size)

const char *sf_file_writer_get_index_filename(const char *data_path,
        const char *subdir_name, char *filename, const int size)
{
    GET_BINLOG_INDEX_FILENAME_EX(data_path, subdir_name, filename, size);
    return filename;
}

static int write_to_binlog_index_file(SFFileWriterInfo *writer)
{
    char filename[PATH_MAX];
    char buff[256];
    int result;
    int len;

    GET_BINLOG_INDEX_FILENAME(writer, filename, sizeof(filename));
    len = sprintf(buff, "%s=%d\n"
            "%s=%d\n",
            BINLOG_INDEX_ITEM_CURRENT_WRITE,
            writer->binlog.index,
            BINLOG_INDEX_ITEM_CURRENT_COMPRESS,
            writer->binlog.compress_index);
    if ((result=safeWriteToFile(filename, buff, len)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "write to file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, filename, result, STRERROR(result));
    }

    return result;
}

static int get_binlog_info_from_file(const char *data_path,
        const char *subdir_name, int *write_index,
        int *compress_index)
{
    char full_filename[PATH_MAX];
    IniContext ini_context;
    int result;

    snprintf(full_filename, sizeof(full_filename), "%s/%s/%s",
            data_path, subdir_name, BINLOG_INDEX_FILENAME);
    if (access(full_filename, F_OK) != 0) {
        return errno != 0 ? errno : EPERM;
    }

    if ((result=iniLoadFromFile(full_filename, &ini_context)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "load from file \"%s\" fail, error code: %d",
                __LINE__, full_filename, result);
        return result;
    }

    *write_index = iniGetIntValue(NULL,
            BINLOG_INDEX_ITEM_CURRENT_WRITE,
            &ini_context, 0);
    *compress_index = iniGetIntValue(NULL,
            BINLOG_INDEX_ITEM_CURRENT_COMPRESS,
            &ini_context, 0);

    iniFreeContext(&ini_context);
    return 0;
}

int sf_file_writer_get_binlog_index(const char *data_path,
        const char *subdir_name, int *write_index)
{
    int compress_index;
    return get_binlog_info_from_file(data_path, subdir_name,
            write_index, &compress_index);
}

static inline int get_binlog_index_from_file(SFFileWriterInfo *writer)
{
    int result;

    result = get_binlog_info_from_file(writer->cfg.data_path,
            writer->cfg.subdir_name, &writer->binlog.index,
            &writer->binlog.compress_index);
    if (result == ENOENT) {
        writer->binlog.index = 0;
        writer->binlog.compress_index = 0;
        return write_to_binlog_index_file(writer);
    }
    return result;
}

static int open_writable_binlog(SFFileWriterInfo *writer)
{
    if (writer->file.fd >= 0) {
        close(writer->file.fd);
    }

    GET_BINLOG_FILENAME(writer);
    writer->file.fd = open(writer->file.name,
            O_WRONLY | O_CREAT | O_APPEND, 0644);
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

    if (fsync(writer->file.fd) != 0) {
        result = errno != 0 ? errno : EIO;
        logError("file: "__FILE__", line: %d, "
                "fsync to binlog file \"%s\" fail, "
                "errno: %d, error info: %s",
                __LINE__, writer->file.name,
                result, STRERROR(result));
        return result;
    }

    writer->file.size += len;
    return 0;
}

static int check_write_to_file(SFFileWriterInfo *writer,
        char *buff, const int len)
{
    int result;

    if (writer->file.size + len <= SF_BINLOG_FILE_MAX_SIZE) {
        return do_write_to_file(writer, buff, len);
    }

    writer->binlog.index++;  //binlog rotate
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

    len = SF_BINLOG_BUFFER_LENGTH(writer->binlog_buffer);
    if (len == 0) {
        return 0;
    }

    result = check_write_to_file(writer, writer->binlog_buffer.buff, len);
    writer->binlog_buffer.end = writer->binlog_buffer.buff;
    return result;
}

int sf_file_writer_get_current_index(SFFileWriterInfo *writer)
{
    if (writer == NULL) {   //for data recovery
        return 0;
    }

    if (writer->binlog.index < 0) {
        get_binlog_index_from_file(writer);
    }

    return writer->binlog.index;
}

int sf_file_writer_deal_versioned_buffer(SFFileWriterInfo *writer,
        BufferInfo *buffer, const int64_t version)
{
    int result;

    if (buffer->length >= writer->binlog_buffer.size / 4) {
        if (SF_BINLOG_BUFFER_LENGTH(writer->binlog_buffer) > 0) {
            if ((result=sf_file_writer_flush(writer)) != 0) {
                return result;
            }
        }

        if ((result=check_write_to_file(writer, buffer->buff,
                        buffer->length)) == 0)
        {
            if (writer->flags & SF_FILE_WRITER_FLAGS_WANT_DONE_VERSION) {
                writer->last_versions.pending = version;
            }
        }
        return result;
    }

    if (writer->file.size + SF_BINLOG_BUFFER_LENGTH(writer->
                binlog_buffer) + buffer->length > SF_BINLOG_FILE_MAX_SIZE)
    {
        if ((result=sf_file_writer_flush(writer)) != 0) {
            return result;
        }
    } else if (writer->binlog_buffer.size - SF_BINLOG_BUFFER_LENGTH(
                writer->binlog_buffer) < buffer->length)
    {
        if ((result=sf_file_writer_flush(writer)) != 0) {
            return result;
        }
    }

    if (writer->flags & SF_FILE_WRITER_FLAGS_WANT_DONE_VERSION) {
        writer->last_versions.pending = version;
    }
    memcpy(writer->binlog_buffer.end, buffer->buff, buffer->length);
    writer->binlog_buffer.end += buffer->length;

    return 0;
}

int sf_file_writer_init(SFFileWriterInfo *writer,
        const char *data_path, const char *subdir_name,
        const int buffer_size)
{
    int result;
    int path_len;
    bool create;
    char filepath[PATH_MAX];

    writer->total_count = 0;
    writer->last_versions.pending = 0;
    writer->last_versions.done = 0;
    writer->flags = 0;
    if ((result=sf_binlog_buffer_init(&writer->
                    binlog_buffer, buffer_size)) != 0)
    {
        return result;
    }

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

int sf_file_writer_set_binlog_index(SFFileWriterInfo *writer,
        const int binlog_index)
{
    int result;

    if (writer->binlog.index != binlog_index) {
        writer->binlog.index = binlog_index;
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
    int remain_count;
    int current_count;
    int current_index;
    int i;
    char filename[PATH_MAX];
    string_t lines;

    current_index = current_write_index;
    *length = 0;
    remain_count = *count;
    for (i=0; i<2; i++) {
        current_count = remain_count;
        sf_file_writer_get_filename(data_path, subdir_name,
                current_index, filename, sizeof(filename));
        result = fc_get_last_lines(filename, buff + *length,
                buff_size - *length, &lines, &current_count);
        if (result == 0) {
            memmove(buff + *length, lines.str, lines.len);
            *length += lines.len;
            remain_count -= current_count;
            if (remain_count == 0) {
                break;
            }
        } else if (result != ENOENT) {
            *count = 0;
            return result;
        }
        if (current_index == 0) {
            break;
        }

        --current_index;  //try previous binlog file
    }

    *count -= remain_count;
    return 0;
}
