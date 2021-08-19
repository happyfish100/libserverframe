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

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <errno.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "sf_serialize.h"

int sf_serialize_unpack(SFSerializeIterator *it, const string_t *content)
{
    SFSerializePackHeader *header;
    int length;
    int calc_crc32;
    int header_crc32;

    if (content->len < sizeof(SFSerializePackHeader)) {
        snprintf(it->error_info, sizeof(it->error_info),
                "content length: %d is too small which < %d",
                content->len, (int)sizeof(SFSerializePackHeader));
        return EINVAL;
    }

    header = (SFSerializePackHeader *)content->str;
    length = buff2int(header->length);
    if (content->len != length + sizeof(SFSerializePackHeader)) {
        snprintf(it->error_info, sizeof(it->error_info),
                "content length: %d != %d", content->len,
                (int)(length + sizeof(SFSerializePackHeader)));
        return EINVAL;
    }

    calc_crc32 = CRC32(header + 1, length);
    header_crc32 = buff2int(header->crc32);
    if (header_crc32 != calc_crc32) {
        snprintf(it->error_info, sizeof(it->error_info),
                "header crc32: %d != calculated: %d",
                header_crc32, calc_crc32);
        return EINVAL;
    }

    it->p = (const char *)(header + 1);
    it->end = content->str + content->len;
    return 0;
}

static int check_field_type(SFSerializeIterator *it,
        const int remain_len, const SFSerializeValueType type)
{
    int min_size;

    switch (type) {
        case sf_serialize_value_type_int8:
            min_size = sizeof(SFSerializePackFieldInt8);
            break;
        case sf_serialize_value_type_int16:
            min_size = sizeof(SFSerializePackFieldInt16);
            break;
        case sf_serialize_value_type_int32:
            min_size = sizeof(SFSerializePackFieldInt32);
            break;
        case sf_serialize_value_type_int64:
            min_size = sizeof(SFSerializePackFieldInt64);
            break;
        case sf_serialize_value_type_string:
            min_size = sizeof(SFSerializePackFieldString);
            break;
        case sf_serialize_value_type_int32_array:
        case sf_serialize_value_type_int64_array:
        case sf_serialize_value_type_map:
            min_size = sizeof(SFSerializePackFieldArray);
            break;
        default:
            snprintf(it->error_info, sizeof(it->error_info),
                    "unknown type: %d", type);
            return EINVAL;
    }

    if (remain_len < min_size) {
        snprintf(it->error_info, sizeof(it->error_info),
                "remain length: %d is too small which < %d",
                remain_len, min_size);
        return EINVAL;
    }
    return 0;
}

static inline int check_string_value(SFSerializeIterator *it,
        const int remain_len, const string_t *s)
{
    if (s->len < 0) {
        snprintf(it->error_info, sizeof(it->error_info),
                "invalid string length: %d < 0", s->len);
        return EINVAL;
    }

    if (s->len > remain_len) {
        snprintf(it->error_info, sizeof(it->error_info),
                "string length: %d is too large > remain length: %d",
                s->len, remain_len);
        return EINVAL;
    }

    return 0;
}

const SFSerializeFieldValue *sf_serialize_next(SFSerializeIterator *it)
{
    int remain_len;
    SFSerializePackFieldInfo *field;
    SFSerializePackFieldString *fs;

    remain_len = it->end - it->p;
    if (remain_len == 0) {
        return NULL;
    }

    if (remain_len <= sizeof(SFSerializePackFieldInfo)) {
        snprintf(it->error_info, sizeof(it->error_info),
                "remain length: %d is too small which <= %d",
                remain_len, (int)sizeof(SFSerializePackFieldInfo));
        it->error_no = EINVAL;
        return NULL;
    }

    field = (SFSerializePackFieldInfo *)it->p;

    it->field.fid = field->id;
    it->field.type = field->type;
    if ((it->error_no=check_field_type(it, remain_len, field->type)) != 0) {
        return NULL;
    }

    switch (field->type) {
        case sf_serialize_value_type_int8:
            it->field.value.n = ((SFSerializePackFieldInt8 *)it->p)->value;
            it->p += sizeof(SFSerializePackFieldInt8);
            break;
        case sf_serialize_value_type_int16:
            it->field.value.n = buff2short(
                    ((SFSerializePackFieldInt16 *)
                     it->p)->value);
            it->p += sizeof(SFSerializePackFieldInt16);
            break;
        case sf_serialize_value_type_int32:
            it->field.value.n = buff2int(
                    ((SFSerializePackFieldInt32 *)
                     it->p)->value);
            it->p += sizeof(SFSerializePackFieldInt32);
            break;
        case sf_serialize_value_type_int64:
            it->field.value.n = buff2long(
                    ((SFSerializePackFieldInt64 *)
                     it->p)->value);
            it->p += sizeof(SFSerializePackFieldInt64);
            break;
        case sf_serialize_value_type_string:
            fs = (SFSerializePackFieldString *)it->p;
            it->field.value.s.len = buff2int(fs->value.len);
            it->field.value.s.str = fs->value.str;
            if ((it->error_no=check_string_value(it, remain_len -
                            sizeof(SFSerializePackFieldString),
                            &it->field.value.s)) != 0)
            {
                return NULL;
            }
            it->p += sizeof(SFSerializePackFieldString) +
                it->field.value.s.len;
            break;
        case sf_serialize_value_type_int32_array:
        case sf_serialize_value_type_int64_array:
        case sf_serialize_value_type_map:
        default:
            snprintf(it->error_info, sizeof(it->error_info),
                    "unknown type: %d", field->type);
            it->error_no = EINVAL;
            return NULL;
    }

    return &it->field;
}
