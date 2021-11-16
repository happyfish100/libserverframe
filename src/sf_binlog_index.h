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

//sf_binlog_index.h

#ifndef _SF_BINLOG_INDEX_H_
#define _SF_BINLOG_INDEX_H_

#include "fastcommon/common_define.h"

#define SF_BINLOG_PARSE_INT_SILENCE(var, caption, index, endchr, min_val) \
    do {   \
        var = strtoll(cols[index].str, &endptr, 10);  \
        if (*endptr != endchr || var < min_val) {    \
            sprintf(error_info, "invalid %s: %.*s",  \
                    caption, cols[index].len, cols[index].str); \
            return EINVAL;  \
        }  \
    } while (0)

#define SF_BINLOG_PARSE_INT_SILENCE2(var, caption, index, echr1, echr2, min_val) \
    do {   \
        var = strtoll(cols[index].str, &endptr, 10);  \
        if (!(*endptr == echr1 || *endptr == echr2) || (var < min_val)) { \
            sprintf(error_info, "invalid %s: %.*s",  \
                    caption, cols[index].len, cols[index].str); \
            return EINVAL;  \
        }  \
    } while (0)


typedef int (*pack_record_func)(char *buff, void *record);
typedef int (*unpack_record_func)(const string_t *line,
        void *record, char *error_info);

typedef struct sf_binlog_index_array {
    void *indexes;
    int alloc;
    int count;
} SFBinlogIndexArray;

typedef struct sf_binlog_index_context {
    const char *name;
    char *filename;
    int record_max_size;
    int array_elt_size;
    pack_record_func pack_record;
    unpack_record_func unpack_record;
    SFBinlogIndexArray index_array;
    int64_t last_version;
} SFBinlogIndexContext;

#ifdef __cplusplus
extern "C" {
#endif

void sf_binlog_index_init(SFBinlogIndexContext *ctx, const char *name,
        const char *filename, const int record_max_size,
        const int array_elt_size, pack_record_func pack_record,
        unpack_record_func unpack_record);

int sf_binlog_index_load(SFBinlogIndexContext *ctx);

int sf_binlog_index_save(SFBinlogIndexContext *ctx);

int sf_binlog_index_expand_array(SFBinlogIndexArray *array,
        const int elt_size);

static inline int sf_binlog_index_expand(SFBinlogIndexContext *ctx)
{
    return sf_binlog_index_expand_array(&ctx->
            index_array, ctx->array_elt_size);
}

static inline void sf_binlog_index_free(SFBinlogIndexContext *ctx)
{
    if (ctx->index_array.indexes != NULL) {
        free(ctx->index_array.indexes);
        ctx->index_array.indexes = NULL;
        ctx->index_array.alloc = ctx->index_array.count = 0;
    }
}

#ifdef __cplusplus
}
#endif

#endif
