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

#define FIELD_ID_AND_TYPE_FORMAT  "fid: %d, type: %s"
#define FIELD_ID_AND_TYPE_PARAMS  it->field.fid, \
    value_type_configs[it->field.type].name


typedef struct {
    const char *name;
    int min_size;
    int elt_size;
} SFSerializeTypeConfig;

static SFSerializeTypeConfig value_type_configs[SF_SERIALIZE_VALUE_TYPE_COUNT] =
{
    {"int8",   sizeof(SFSerializePackFieldInt8),   0},
    {"int16",  sizeof(SFSerializePackFieldInt16),  0},
    {"int32",  sizeof(SFSerializePackFieldInt32),  0},
    {"int64",  sizeof(SFSerializePackFieldInt64),  0},
    {"string", sizeof(SFSerializePackStringValue), 0},
    {"int32_array", sizeof(SFSerializePackFieldArray), 4},
    {"int64_array", sizeof(SFSerializePackFieldArray), 8},
    {"map", sizeof(SFSerializePackFieldArray), 2 *
        sizeof(SFSerializePackStringValue)}
};

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
    if (!(type >= 0 && type < SF_SERIALIZE_VALUE_TYPE_COUNT)) {
        snprintf(it->error_info, sizeof(it->error_info),
                "fid: %d, unknown type: %d", it->field.fid, type);
        return EINVAL;
    }

    if (remain_len < value_type_configs[type].min_size) {
        snprintf(it->error_info, sizeof(it->error_info),
                FIELD_ID_AND_TYPE_FORMAT", remain length: %d "
                "is too small which < %d", FIELD_ID_AND_TYPE_PARAMS,
                remain_len, value_type_configs[type].min_size);
        return EINVAL;
    }
    return 0;
}

static inline int check_string_value(SFSerializeIterator *it,
        const int remain_len, const string_t *s)
{
    if (s->len < 0) {
        snprintf(it->error_info, sizeof(it->error_info),
                FIELD_ID_AND_TYPE_FORMAT", invalid string length: %d < 0",
                FIELD_ID_AND_TYPE_PARAMS, s->len);
        return EINVAL;
    }

    if (s->len > remain_len) {
        snprintf(it->error_info, sizeof(it->error_info),
                FIELD_ID_AND_TYPE_FORMAT", string length: %d is too "
                "large > remain length: %d", FIELD_ID_AND_TYPE_PARAMS,
                s->len, remain_len);
        return EINVAL;
    }

    return 0;
}

static inline int unpack_array_count(SFSerializeIterator *it,
        const int remain_len, int *count)
{
    int min_size;

    *count = buff2int(((SFSerializePackFieldArray *)it->p)->value.count);
    if (*count < 0) {
        snprintf(it->error_info, sizeof(it->error_info),
                FIELD_ID_AND_TYPE_FORMAT", invalid array count: %d < 0",
                FIELD_ID_AND_TYPE_PARAMS, *count);
        return EINVAL;
    }

    min_size = value_type_configs[it->field.type].elt_size * (*count);
    if (min_size > remain_len) {
        snprintf(it->error_info, sizeof(it->error_info),
                FIELD_ID_AND_TYPE_FORMAT", array min bytes: %d is "
                "too large > remain: %d", FIELD_ID_AND_TYPE_PARAMS,
                min_size, remain_len);
        return EINVAL;
    }

    return 0;
}

static int array_expand(SFSerializeIterator *it, void_array_t *array,
        const int elt_size, const int target_count, int *alloc_size)
{
    int new_alloc;
    void *new_elts;

    if (*alloc_size == 0) {
        new_alloc = 256;
    } else {
        new_alloc = (*alloc_size) * 2;
    }
    while (new_alloc < target_count) {
        new_alloc *= 2;
    }

    new_elts = fc_malloc(elt_size * new_alloc);
    if (new_elts == NULL) {
        snprintf(it->error_info, sizeof(it->error_info),
                FIELD_ID_AND_TYPE_FORMAT", malloc %d bytes fail",
                FIELD_ID_AND_TYPE_PARAMS, elt_size * new_alloc);
        return ENOMEM;
    }

    if (array->elts != NULL) {
        free(array->elts);
    }
    array->elts = new_elts;
    *alloc_size = new_alloc;
    return 0;
}

static inline int unpack_string(SFSerializeIterator *it, const int remain_len,
        SFSerializePackStringValue *input, string_t *output)
{
    if (remain_len < sizeof(SFSerializePackStringValue)) {
        snprintf(it->error_info, sizeof(it->error_info),
                FIELD_ID_AND_TYPE_FORMAT", remain length: %d "
                "is too small < %d", FIELD_ID_AND_TYPE_PARAMS,
                remain_len, (int)sizeof(SFSerializePackStringValue));
        return EINVAL;
    }

    output->len = buff2int(input->len);
    output->str = input->str;
    it->p += sizeof(SFSerializePackStringValue) + output->len;
    return check_string_value(it, remain_len -
            sizeof(SFSerializePackStringValue), output);
}

static int unpack_array(SFSerializeIterator *it, const int remain_len)
{
    int result;
    int count;
    int64_t *pn;
    int64_t *end;

    if ((result=unpack_array_count(it, remain_len, &count)) != 0) {
        return result;
    }

    if (count > it->int_array_alloc) {
        if ((result=array_expand(it, (void_array_t *)&it->int_array,
                        sizeof(int64_t), count, &it->int_array_alloc)) != 0)
        {
            return result;
        }
    }

    it->p += sizeof(SFSerializePackFieldArray);
    end = it->int_array.elts + count;
    for (pn=it->int_array.elts; pn<end; pn++) {
        if (it->field.type == sf_serialize_value_type_int32_array) {
            *pn = buff2int(it->p);
        } else {
            *pn = buff2long(it->p);
        }
        it->p += value_type_configs[it->field.type].elt_size;
    }
    it->int_array.count = count;

    return 0;
}

static int unpack_map(SFSerializeIterator *it, const int remain_len)
{
    int result;
    int count;
    key_value_pair_t *pair;
    key_value_pair_t *end;

    if ((result=unpack_array_count(it, remain_len, &count)) != 0) {
        return result;
    }

    if (count > it->kv_array_alloc) {
        if ((result=array_expand(it, (void_array_t *)&it->kv_array,
                        sizeof(key_value_pair_t), count,
                        &it->kv_array_alloc)) != 0)
        {
            return result;
        }
    }

    it->p += sizeof(SFSerializePackFieldArray);
    end = it->kv_array.kv_pairs + count;
    for (pair=it->kv_array.kv_pairs; pair<end; pair++) {
        if ((result=unpack_string(it, it->end - it->p,
                        (SFSerializePackStringValue *)it->p,
                        &pair->key)) != 0)
        {
            return result;
        }
        if ((result=unpack_string(it, it->end - it->p,
                        (SFSerializePackStringValue *)it->p,
                        &pair->value)) != 0)
        {
            return result;
        }
    }
    it->kv_array.count = count;

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
            it->p += sizeof(SFSerializePackFieldInfo);
            if ((it->error_no=unpack_string(it, remain_len -
                            sizeof(SFSerializePackFieldInfo),
                            &fs->value, &it->field.value.s)) != 0)
            {
                return NULL;
            }
            break;
        case sf_serialize_value_type_int32_array:
        case sf_serialize_value_type_int64_array:
            if ((it->error_no=unpack_array(it, remain_len - sizeof(
                                SFSerializePackFieldArray))) != 0)
            {
                return NULL;
            }
            it->field.value.int_array = it->int_array;
            break;
        case sf_serialize_value_type_map:
            if ((it->error_no=unpack_map(it, remain_len - sizeof(
                                SFSerializePackFieldArray))) != 0)
            {
                return NULL;
            }
            it->field.value.kv_array = it->kv_array;
            break;
    }

    return &it->field;
}
