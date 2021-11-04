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

#include "fastcommon/logger.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/fc_memory.h"
#include "sf_binlog_index.h"

#define SF_BINLOG_HEADER_FIELD_COUNT   2
#define SF_BINLOG_HEADER_FIELD_INDEX_RECORD_COUNT  0
#define SF_BINLOG_HEADER_FIELD_INDEX_LAST_VERSION  1

void sf_binlog_index_init(SFBinlogIndexContext *ctx, const char *name,
        const char *filename, const int record_max_size,
        const int array_elt_size, pack_record_func pack_record,
        unpack_record_func unpack_record)
{
    memset(ctx, 0, sizeof(SFBinlogIndexContext));
    ctx->name = name;
    ctx->filename = fc_strdup(filename);
    ctx->record_max_size = record_max_size;
    ctx->array_elt_size = array_elt_size;
    ctx->pack_record = pack_record;
    ctx->unpack_record = unpack_record;
}

static int parse_header(const string_t *line, int *record_count,
        int64_t *last_version, char *error_info)
{
    int count;
    char *endptr;
    string_t cols[SF_BINLOG_HEADER_FIELD_COUNT];

    count = split_string_ex(line, ' ', cols,
            SF_BINLOG_HEADER_FIELD_COUNT, false);
    if (count != SF_BINLOG_HEADER_FIELD_COUNT) {
        sprintf(error_info, "field count: %d != %d",
                count, SF_BINLOG_HEADER_FIELD_COUNT);
        return EINVAL;
    }

    SF_BINLOG_PARSE_INT_SILENCE(*record_count, "record count",
            SF_BINLOG_HEADER_FIELD_INDEX_RECORD_COUNT, ' ', 0);
    SF_BINLOG_PARSE_INT_SILENCE(*last_version, "last version",
            SF_BINLOG_HEADER_FIELD_INDEX_LAST_VERSION, '\n', 0);
    return 0;
}

static int parse(SFBinlogIndexContext *ctx, const string_t *lines,
        const int row_count)
{
    int result;
    int record_count;
    char error_info[256];
    const string_t *line;
    const string_t *end;
    void *bindex;

    if (row_count < 1) {
        return EINVAL;
    }

    if ((result=parse_header(lines, &record_count, &ctx->
                    last_version, error_info)) != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "%s index file: %s, parse header fail, error info: %s",
                __LINE__, ctx->name, ctx->filename, error_info);
        return result;
    }

    if (row_count != record_count + 1) {
        logError("file: "__FILE__", line: %d, "
                "%s index file: %s, line count: %d != record count: "
                "%d + 1", __LINE__, ctx->name, ctx->filename,
                row_count, record_count + 1);
        return EINVAL;
    }

    ctx->index_array.alloc = 64;
    while (ctx->index_array.alloc < record_count) {
        ctx->index_array.alloc *= 2;
    }
    ctx->index_array.indexes = fc_malloc(ctx->array_elt_size *
            ctx->index_array.alloc);
    if (ctx->index_array.indexes == NULL) {
        return ENOMEM;
    }

    end = lines + row_count;
    bindex = ctx->index_array.indexes;
    for (line=lines+1; line<end; line++) {
        if ((result=ctx->unpack_record(line, bindex, error_info)) != 0) {
            logError("file: "__FILE__", line: %d, "
                    "%s index file: %s, parse line #%d fail, error "
                    "info: %s", __LINE__, ctx->name, ctx->filename,
                    (int)(line - lines) + 1, error_info);
            return result;
        }

        bindex = (char *)bindex + ctx->array_elt_size;
    }

    ctx->index_array.count = row_count - 1;
    return 0;
}

static int load(SFBinlogIndexContext *ctx)
{
    int result;
    int row_count;
    int64_t file_size;
    string_t context;
    string_t *lines;

    if ((result=getFileContent(ctx->filename, &context.str,
                    &file_size)) != 0)
    {
        return result;
    }

    context.len = file_size;
    row_count = getOccurCount(context.str, '\n');
    lines = (string_t *)fc_malloc(sizeof(string_t) * row_count);
    if (lines == NULL) {
        free(context.str);
        return ENOMEM;
    }

    row_count = split_string_ex(&context, '\n', lines, row_count, true);
    result = parse(ctx, lines, row_count);
    free(lines);
    free(context.str);
    return result;
}

int sf_binlog_index_load(SFBinlogIndexContext *ctx)
{
    int result;

    if (access(ctx->filename, F_OK) == 0) {
        return load(ctx);
    } else if (errno == ENOENT) {
        return 0;
    } else {
        result = errno != 0 ? errno : EPERM;
        logError("file: "__FILE__", line: %d, "
                "access file %s fail, "
                "errno: %d, error info: %s", __LINE__,
                ctx->filename, result, STRERROR(result));
        return result;
    }
}

static int save(SFBinlogIndexContext *ctx, const char *filename)
{
    char buff[16 * 1024];
    char *bend;
    void *index;
    char *p;
    int fd;
    int len;
    int i;
    int result;

    if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644)) < 0) {
        result = errno != 0 ? errno : EIO;
        logError("file: "__FILE__", line: %d, "
                "open file %s fail, errno: %d, error info: %s",
                __LINE__, filename, result, STRERROR(result));
        return result;
    }

    result = 0;
    p = buff;
    bend = buff + sizeof(buff);
    p += sprintf(p, "%d %"PRId64"\n",
            ctx->index_array.count,
            ctx->last_version);

    index = ctx->index_array.indexes;
    for (i=0; i<ctx->index_array.count; i++) {
        if (bend - p < ctx->record_max_size) {
            len = p - buff;
            if (fc_safe_write(fd, buff, len) != len) {
                result = errno != 0 ? errno : EIO;
                logError("file: "__FILE__", line: %d, "
                        "write file %s fail, errno: %d, error info: %s",
                        __LINE__, filename, result, STRERROR(result));
                break;
            }
            p = buff;
        }

        p += ctx->pack_record(p, index);
        index = (char *)index + ctx->array_elt_size;
    }

    if (result == 0) {
        len = p - buff;
        if (len > 0 && fc_safe_write(fd, buff, len) != len) {
            result = errno != 0 ? errno : EIO;
            logError("file: "__FILE__", line: %d, "
                    "write file %s fail, errno: %d, error info: %s",
                    __LINE__, filename, result, STRERROR(result));
        }
    }

    close(fd);
    return result;
}

int sf_binlog_index_save(SFBinlogIndexContext *ctx)
{
    int result;
    char tmp_filename[PATH_MAX];

    snprintf(tmp_filename, sizeof(tmp_filename), "%s.tmp", ctx->filename);
    if ((result=save(ctx, tmp_filename)) != 0) {
        return result;
    }

    if (rename(tmp_filename, ctx->filename) != 0) {
        result = errno != 0 ? errno : EIO;
        logError("file: "__FILE__", line: %d, "
                "rename file \"%s\" to \"%s\" fail, "
                "errno: %d, error info: %s",
                __LINE__, tmp_filename, ctx->filename,
                result, STRERROR(result));
        return result;
    }

    return 0;
}

int sf_binlog_index_expand_array(SFBinlogIndexArray *array,
        const int elt_size)
{
    int alloc;
    void *indexes;

    if (array->alloc == 0) {
        alloc = 1024;
    } else {
        alloc = array->alloc * 2;
    }
    indexes = fc_malloc(elt_size * alloc);
    if (indexes == NULL) {
        return ENOMEM;
    }

    if (array->count > 0) {
        memcpy(indexes, array->indexes, elt_size * array->count);
        free(array->indexes);
    }

    array->indexes = indexes;
    array->alloc = alloc;
    return 0;
}
