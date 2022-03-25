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

//sf_buffered_writer.h

#ifndef _SF_BUFFERED_WRITER_H_
#define _SF_BUFFERED_WRITER_H_

#include "sf_types.h"
#include "sf_func.h"

typedef struct {
    int fd;
    const char *filename;
    SFBinlogBuffer buffer;
} SFBufferedWriter;

#define sf_buffered_writer_init(writer, filename) \
    sf_buffered_writer_init_ex(writer, filename, 1024 * 1024)

#define SF_BUFFERED_WRITER_LENGTH(bw) ((bw).buffer.current - (bw).buffer.buff)
#define SF_BUFFERED_WRITER_REMAIN(bw) ((bw).buffer.end - (bw).buffer.current)

#ifdef __cplusplus
extern "C" {
#endif

    static inline int sf_buffered_writer_init_ex(SFBufferedWriter *writer,
            const char *filename, const int buffer_size)
    {
        int result;

        writer->filename = filename;
        writer->fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (writer->fd < 0) {
            result = errno != 0 ? errno : EIO;
            logError("file: "__FILE__", line: %d, "
                    "open file %s fail, errno: %d, error info: %s",
                    __LINE__, filename, result, STRERROR(result));
            return result;
        }

        if ((result=sf_binlog_buffer_init(&writer->buffer, buffer_size)) != 0) {
            return result;
        }
        writer->buffer.end = writer->buffer.buff + writer->buffer.size;
        return 0;
    }

    static inline int sf_buffered_writer_save(SFBufferedWriter *writer)
    {
        int result;
        int length;

        length = writer->buffer.current - writer->buffer.buff;
        if (fc_safe_write(writer->fd, writer->buffer.buff, length) != length) {
            result = errno != 0 ? errno : EIO;
            logError("file: "__FILE__", line: %d, "
                    "write to file %s fail, errno: %d, error info: %s",
                    __LINE__, writer->filename, result, STRERROR(result));
            return result;
        }

        writer->buffer.current = writer->buffer.buff;
        return 0;
    }

    static inline void sf_buffered_writer_destroy(SFBufferedWriter *writer)
    {
        if (writer->fd >= 0) {
            close(writer->fd);
            writer->fd = -1;
        }
        sf_binlog_buffer_destroy(&writer->buffer);
    }

#ifdef __cplusplus
}
#endif

#endif
