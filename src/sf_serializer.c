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
#include "sf_serializer.h"

#define FIELD_ID_AND_TYPE_FORMAT  "fid: %d, type: %s"
#define FIELD_ID_AND_TYPE_PARAMS  it->field.fid, \
    value_type_configs[it->field.type].name


typedef struct {
    const char *name;
    int min_size;
    int elt_size;
} SFSerializerTypeConfig;

static SFSerializerTypeConfig value_type_configs[SF_SERIALIZER_VALUE_TYPE_COUNT] =
{
    {"int8",   sizeof(SFSerializerPackFieldInt8),   0},
    {"int16",  sizeof(SFSerializerPackFieldInt16),  0},
    {"int32",  sizeof(SFSerializerPackFieldInt32),  0},
    {"int64",  sizeof(SFSerializerPackFieldInt64),  0},
    {"string", sizeof(SFSerializerPackStringValue), 0},
    {"int8_array",  sizeof(SFSerializerPackFieldArray), 1},
    {"int16_array", sizeof(SFSerializerPackFieldArray), 2},
    {"int32_array", sizeof(SFSerializerPackFieldArray), 4},
    {"int64_array", sizeof(SFSerializerPackFieldArray), 8},
    {"string_array", sizeof(SFSerializerPackFieldArray),
        sizeof(SFSerializerPackStringValue)},
    {"id_name_array", sizeof(SFSerializerPackFieldArray),
        sizeof(int64_t) + sizeof(SFSerializerPackStringValue)},
    {"map", sizeof(SFSerializerPackFieldArray), 2 *
        sizeof(SFSerializerPackStringValue)}
};

int sf_serializer_unpack(SFSerializerIterator *it, const string_t *content)
{
    SFSerializerPackHeader *header;
    int length;
    int calc_crc32;
    int header_crc32;

    if (content->len < sizeof(SFSerializerPackHeader)) {
        snprintf(it->error_info, sizeof(it->error_info),
                "content length: %d is too small which < %d",
                content->len, (int)sizeof(SFSerializerPackHeader));
        return EINVAL;
    }

    header = (SFSerializerPackHeader *)content->str;
    length = buff2int(header->length);
    if (content->len != length + sizeof(SFSerializerPackHeader)) {
        snprintf(it->error_info, sizeof(it->error_info),
                "content length: %d != %d", content->len,
                (int)(length + sizeof(SFSerializerPackHeader)));
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

static int check_field_type(SFSerializerIterator *it,
        const int remain_len, const SFSerializerValueType type)
{
    if (!(type >= 0 && type < SF_SERIALIZER_VALUE_TYPE_COUNT)) {
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

static inline int check_string_value(SFSerializerIterator *it,
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

static inline int unpack_array_count(SFSerializerIterator *it,
        const int remain_len, int *count)
{
    int min_size;

    *count = buff2int(((SFSerializerPackFieldArray *)it->p)->value.count);
    if (*count < 0) {
        snprintf(it->error_info, sizeof(it->error_info),
                FIELD_ID_AND_TYPE_FORMAT", invalid array count: %d < 0",
                FIELD_ID_AND_TYPE_PARAMS, *count);
        return EINVAL;
    }

    min_size = value_type_configs[it->field.type].elt_size * (*count);
    if (remain_len < min_size) {
        snprintf(it->error_info, sizeof(it->error_info),
                FIELD_ID_AND_TYPE_FORMAT", remain length: %d is too "
                "small < array min bytes: %d", FIELD_ID_AND_TYPE_PARAMS,
                remain_len, min_size);
        return EINVAL;
    }

    return 0;
}

static int array_expand(SFSerializerIterator *it, void_array_t *array,
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

static inline int unpack_string(SFSerializerIterator *it, const int remain_len,
        SFSerializerPackStringValue *input, string_t *output)
{
    if (remain_len < sizeof(SFSerializerPackStringValue)) {
        snprintf(it->error_info, sizeof(it->error_info),
                FIELD_ID_AND_TYPE_FORMAT", remain length: %d "
                "is too small < %d", FIELD_ID_AND_TYPE_PARAMS,
                remain_len, (int)sizeof(SFSerializerPackStringValue));
        return EINVAL;
    }

    output->len = buff2int(input->len);
    output->str = input->str;
    it->p += sizeof(SFSerializerPackStringValue) + output->len;
    return check_string_value(it, remain_len -
            sizeof(SFSerializerPackStringValue), output);
}

static int unpack_integer_array(SFSerializerIterator *it, const int remain_len)
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

    it->p += sizeof(SFSerializerPackFieldArray);
    end = it->int_array.elts + count;
    for (pn=it->int_array.elts; pn<end; pn++) {
        switch (it->field.type) {
            case sf_serializer_value_type_int8_array:
                *pn = *it->p;
                break;
            case sf_serializer_value_type_int16_array:
                *pn = buff2short(it->p);
                break;
            case sf_serializer_value_type_int32_array:
                *pn = buff2int(it->p);
                break;
            default:
                *pn = buff2long(it->p);
                break;
        }
        it->p += value_type_configs[it->field.type].elt_size;
    }
    it->int_array.count = count;

    return 0;
}

static int unpack_string_array(SFSerializerIterator *it, const int remain_len)
{
    int result;
    int count;
    string_t *str;
    string_t *end;

    if ((result=unpack_array_count(it, remain_len, &count)) != 0) {
        return result;
    }

    if (count > it->str_array_alloc) {
        if ((result=array_expand(it, (void_array_t *)&it->str_array,
                        sizeof(string_t), count, &it->str_array_alloc)) != 0)
        {
            return result;
        }
    }

    it->p += sizeof(SFSerializerPackFieldArray);
    end = it->str_array.strings + count;
    for (str=it->str_array.strings; str<end; str++) {
        if ((result=unpack_string(it, it->end - it->p,
                        (SFSerializerPackStringValue *)
                        it->p, str)) != 0)
        {
            return result;
        }
    }
    it->str_array.count = count;

    return 0;
}

static int unpack_id_name_array(SFSerializerIterator *it, const int remain_len)
{
    int result;
    int count;
    id_name_pair_t *pair;
    id_name_pair_t *end;

    if ((result=unpack_array_count(it, remain_len, &count)) != 0) {
        return result;
    }

    if (count > it->id_name_array_alloc) {
        if ((result=array_expand(it, (void_array_t *)&it->id_name_array,
                        sizeof(id_name_pair_t), count,
                        &it->id_name_array_alloc)) != 0)
        {
            return result;
        }
    }

    it->p += sizeof(SFSerializerPackFieldArray);
    end = it->id_name_array.elts + count;
    for (pair=it->id_name_array.elts; pair<end; pair++) {
        if ((it->end - it->p) < (sizeof(int64_t) +
                    sizeof(SFSerializerPackStringValue)))
        {
            snprintf(it->error_info, sizeof(it->error_info),
                    FIELD_ID_AND_TYPE_FORMAT", remain length: %d "
                    "is too small < %d", FIELD_ID_AND_TYPE_PARAMS,
                    (int)(it->end - it->p), (int)(sizeof(int64_t) +
                        sizeof(SFSerializerPackStringValue)));
            return EINVAL;
        }

        pair->id = buff2long(it->p);
        it->p += sizeof(int64_t);
        if ((result=unpack_string(it, it->end - it->p,
                        (SFSerializerPackStringValue *)it->p,
                        &pair->name)) != 0)
        {
            return result;
        }
    }
    it->id_name_array.count = count;

    return 0;
}

static int unpack_map(SFSerializerIterator *it, const int remain_len)
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

    it->p += sizeof(SFSerializerPackFieldArray);
    end = it->kv_array.kv_pairs + count;
    for (pair=it->kv_array.kv_pairs; pair<end; pair++) {
        if ((result=unpack_string(it, it->end - it->p,
                        (SFSerializerPackStringValue *)it->p,
                        &pair->key)) != 0)
        {
            return result;
        }
        if ((result=unpack_string(it, it->end - it->p,
                        (SFSerializerPackStringValue *)it->p,
                        &pair->value)) != 0)
        {
            return result;
        }
    }
    it->kv_array.count = count;

    return 0;
}

const SFSerializerFieldValue *sf_serializer_next(SFSerializerIterator *it)
{
    int remain_len;
    SFSerializerPackFieldInfo *field;
    SFSerializerPackFieldString *fs;

    remain_len = it->end - it->p;
    if (remain_len == 0) {
        return NULL;
    }

    if (remain_len <= sizeof(SFSerializerPackFieldInfo)) {
        snprintf(it->error_info, sizeof(it->error_info),
                "remain length: %d is too small which <= %d",
                remain_len, (int)sizeof(SFSerializerPackFieldInfo));
        it->error_no = EINVAL;
        return NULL;
    }

    field = (SFSerializerPackFieldInfo *)it->p;
    it->field.fid = field->id;
    it->field.type = field->type;
    if ((it->error_no=check_field_type(it, remain_len, field->type)) != 0) {
        return NULL;
    }

    switch (field->type) {
        case sf_serializer_value_type_int8:
            it->field.value.n = ((SFSerializerPackFieldInt8 *)it->p)->value;
            it->p += sizeof(SFSerializerPackFieldInt8);
            break;
        case sf_serializer_value_type_int16:
            it->field.value.n = buff2short(
                    ((SFSerializerPackFieldInt16 *)
                     it->p)->value);
            it->p += sizeof(SFSerializerPackFieldInt16);
            break;
        case sf_serializer_value_type_int32:
            it->field.value.n = buff2int(
                    ((SFSerializerPackFieldInt32 *)
                     it->p)->value);
            it->p += sizeof(SFSerializerPackFieldInt32);
            break;
        case sf_serializer_value_type_int64:
            it->field.value.n = buff2long(
                    ((SFSerializerPackFieldInt64 *)
                     it->p)->value);
            it->p += sizeof(SFSerializerPackFieldInt64);
            break;
        case sf_serializer_value_type_string:
            fs = (SFSerializerPackFieldString *)it->p;
            it->p += sizeof(SFSerializerPackFieldInfo);
            if ((it->error_no=unpack_string(it, remain_len -
                            sizeof(SFSerializerPackFieldInfo),
                            &fs->value, &it->field.value.s)) != 0)
            {
                return NULL;
            }
            break;
        case sf_serializer_value_type_int8_array:
        case sf_serializer_value_type_int16_array:
        case sf_serializer_value_type_int32_array:
        case sf_serializer_value_type_int64_array:
            if ((it->error_no=unpack_integer_array(it, remain_len -
                            sizeof(SFSerializerPackFieldArray))) != 0)
            {
                return NULL;
            }
            it->field.value.int_array = it->int_array;
            break;
        case sf_serializer_value_type_string_array:
            if ((it->error_no=unpack_string_array(it, remain_len - sizeof(
                                SFSerializerPackFieldArray))) != 0)
            {
                return NULL;
            }
            it->field.value.str_array = it->str_array;
            break;
        case sf_serializer_value_type_id_name_array:
            if ((it->error_no=unpack_id_name_array(it, remain_len -
                            sizeof(SFSerializerPackFieldArray))) != 0)
            {
                return NULL;
            }
            it->field.value.id_name_array = it->id_name_array;
            break;
        case sf_serializer_value_type_map:
            if ((it->error_no=unpack_map(it, remain_len - sizeof(
                                SFSerializerPackFieldArray))) != 0)
            {
                return NULL;
            }
            it->field.value.kv_array = it->kv_array;
            break;
    }

    return &it->field;
}

int sf_serializer_read_message(int fd, BufferInfo *buffer,
        const int max_size)
{
    SFSerializerPackHeader *header;
    char *new_buff;
    int new_alloc;
    int length;
    int total_bytes;

    if (fc_safe_read(fd, buffer->buff, sizeof(*header)) != sizeof(*header)) {
        return ENODATA;
    }

    header = (SFSerializerPackHeader *)buffer->buff;
    length = buff2int(header->length);
    if (length <= 0 || length > max_size) {
        return EINVAL;
    }

    total_bytes = sizeof(*header) + length;
    if (buffer->alloc_size < total_bytes) {
        new_alloc = buffer->alloc_size * 2;
        while (new_alloc < total_bytes) {
            new_alloc *= 2;
        }

        new_buff = (char *)fc_malloc(new_alloc);
        if (new_buff == NULL) {
            return ENOMEM;
        }

        memcpy(new_buff, buffer->buff, sizeof(*header));
        free(buffer->buff);
        buffer->buff = new_buff;
        buffer->alloc_size = new_alloc;
    }

    if (fc_safe_read(fd, buffer->buff + sizeof(*header),
                length) != length)
    {
        return ENODATA;
    }

    buffer->length = total_bytes;
    return 0;
}
