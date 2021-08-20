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

//sf_serialize.h

#ifndef _SF_SERIALIZE_H
#define _SF_SERIALIZE_H

#include "fastcommon/common_define.h"
#include "fastcommon/fast_buffer.h"
#include "fastcommon/hash.h"

#define SF_SERIALIZE_VALUE_TYPE_COUNT  8

typedef enum {
    sf_serialize_value_type_int8 = 0,
    sf_serialize_value_type_int16,
    sf_serialize_value_type_int32,
    sf_serialize_value_type_int64,
    sf_serialize_value_type_string,
    sf_serialize_value_type_int32_array,
    sf_serialize_value_type_int64_array,
    sf_serialize_value_type_map
} SFSerializeValueType;

typedef struct sf_serialize_pack_header {
    char length[4];
    char crc32[4];
} SFSerializePackHeader;

typedef struct sf_serialize_pack_field_info {
    unsigned char id;
    unsigned char type;
} SFSerializePackFieldInfo;

typedef struct sf_serialize_pack_field_int8 {
    SFSerializePackFieldInfo field;
    char value;
} SFSerializePackFieldInt8;

typedef struct sf_serialize_pack_field_int16 {
    SFSerializePackFieldInfo field;
    char value[2];
} SFSerializePackFieldInt16;

typedef struct sf_serialize_pack_field_int32 {
    SFSerializePackFieldInfo field;
    char value[4];
} SFSerializePackFieldInt32;

typedef struct sf_serialize_pack_field_int64 {
    SFSerializePackFieldInfo field;
    char value[8];
} SFSerializePackFieldInt64;

typedef struct sf_serialize_pack_string_value {
    char len[4];
    char str[0];
} SFSerializePackStringValue;

typedef struct sf_serialize_pack_field_string {
    SFSerializePackFieldInfo field;
    SFSerializePackStringValue value;
} SFSerializePackFieldString;

typedef struct sf_serialize_pack_field_array {
    SFSerializePackFieldInfo field;
    struct {
        char count[4];
        char ptr[0];
    } value;
} SFSerializePackFieldArray;

typedef struct sf_serialize_field_value {
    unsigned char fid;
    SFSerializeValueType type;
    union {
        int64_t n;
        string_t s;
        int64_array_t int_array;
        key_value_array_t kv_array;
    } value;
} SFSerializeFieldValue;

typedef struct sf_serialize_iterator {
    const char *p;
    const char *end;
    int64_array_t int_array;     //int64_t array holder
    key_value_array_t kv_array;  //key-value array holder
    int int_array_alloc;
    int kv_array_alloc;
    SFSerializeFieldValue field;
    int error_no;
    char error_info[256];
} SFSerializeIterator;

#ifdef __cplusplus
extern "C" {
#endif

static inline void sf_serialize_pack_begin(FastBuffer *buffer)
{
    buffer->length = sizeof(SFSerializePackHeader);
}

static inline int sf_serialize_pack_int8(FastBuffer *buffer,
        const unsigned char fid, const int8_t value)
{
    int result;
    SFSerializePackFieldInt8 *obj;

    if ((result=fast_buffer_check_inc_size(buffer,
                    sizeof(SFSerializePackFieldInt8))) != 0)
    {
        return result;
    }

    obj = (SFSerializePackFieldInt8 *)(buffer->data + buffer->length);
    obj->field.id = fid;
    obj->field.type = sf_serialize_value_type_int8;
    obj->value = value;
    buffer->length += sizeof(SFSerializePackFieldInt8);
    return 0;
}

static inline int sf_serialize_pack_int16(FastBuffer *buffer,
        const unsigned char fid, const int16_t value)
{
    int result;
    SFSerializePackFieldInt16 *obj;

    if ((result=fast_buffer_check_inc_size(buffer,
                    sizeof(SFSerializePackFieldInt16))) != 0)
    {
        return result;
    }

    obj = (SFSerializePackFieldInt16 *)(buffer->data + buffer->length);
    obj->field.id = fid;
    obj->field.type = sf_serialize_value_type_int16;
    short2buff(value, obj->value);
    buffer->length += sizeof(SFSerializePackFieldInt16);
    return 0;
}

static inline int sf_serialize_pack_int32(FastBuffer *buffer,
        const unsigned char fid, const int32_t value)
{
    int result;
    SFSerializePackFieldInt32 *obj;

    if ((result=fast_buffer_check_inc_size(buffer,
                    sizeof(SFSerializePackFieldInt32))) != 0)
    {
        return result;
    }

    obj = (SFSerializePackFieldInt32 *)(buffer->data + buffer->length);
    obj->field.id = fid;
    obj->field.type = sf_serialize_value_type_int32;
    int2buff(value, obj->value);
    buffer->length += sizeof(SFSerializePackFieldInt32);
    return 0;
}

static inline int sf_serialize_pack_int64(FastBuffer *buffer,
        const unsigned char fid, const int64_t value)
{
    int result;
    SFSerializePackFieldInt64 *obj;

    if ((result=fast_buffer_check_inc_size(buffer,
                    sizeof(SFSerializePackFieldInt64))) != 0)
    {
        return result;
    }

    obj = (SFSerializePackFieldInt64 *)(buffer->data + buffer->length);
    obj->field.id = fid;
    obj->field.type = sf_serialize_value_type_int64;
    long2buff(value, obj->value);
    buffer->length += sizeof(SFSerializePackFieldInt64);
    return 0;
}

#define SF_SERIALIZE_PACK_STRING(ps, value)  \
    int2buff((value)->len, (ps)->len);   \
    memcpy((ps)->str, (value)->str, (value)->len)

#define SF_SERIALIZE_PACK_STRING_AND_MOVE_PTR(ps, value)  \
    SF_SERIALIZE_PACK_STRING(ps, value);  \
    ps = (SFSerializePackStringValue *)(((char *)ps) + sizeof( \
                    SFSerializePackStringValue) + (value)->len)

static inline int sf_serialize_pack_string(FastBuffer *buffer,
        const unsigned char fid, const string_t *value)
{
    int result;
    int length;
    SFSerializePackFieldString *obj;

    length = sizeof(SFSerializePackFieldString) + value->len;
    if ((result=fast_buffer_check_inc_size(buffer, length)) != 0) {
        return result;
    }

    obj = (SFSerializePackFieldString *)(buffer->data + buffer->length);
    obj->field.id = fid;
    obj->field.type = sf_serialize_value_type_string;
    SF_SERIALIZE_PACK_STRING(&obj->value, value);
    buffer->length += length;
    return 0;
}

static inline int sf_serialize_pack_int32_array(FastBuffer *buffer,
        const unsigned char fid, const int32_t *array, const int count)
{
    int result;
    int length;
    SFSerializePackFieldArray *obj;
    const int32_t *pn;
    const int32_t *end;
    char *ps;

    length = sizeof(SFSerializePackFieldArray) + count * 4;
    if ((result=fast_buffer_check_inc_size(buffer, length)) != 0) {
        return result;
    }

    obj = (SFSerializePackFieldArray *)(buffer->data + buffer->length);
    obj->field.id = fid;
    obj->field.type = sf_serialize_value_type_int32_array;
    int2buff(count, obj->value.count);
    end = array + count;
    for (pn=array, ps=obj->value.ptr; pn<end; pn++, ps+=4) {
        int2buff(*pn, ps);
    }
    buffer->length += length;
    return 0;
}

static inline int sf_serialize_pack_int64_array(FastBuffer *buffer,
        const unsigned char fid, const int64_t *array, const int count)
{
    int result;
    int length;
    SFSerializePackFieldArray *obj;
    const int64_t *pn;
    const int64_t *end;
    char *ps;

    length = sizeof(SFSerializePackFieldArray) + count * 8;
    if ((result=fast_buffer_check_inc_size(buffer, length)) != 0) {
        return result;
    }

    obj = (SFSerializePackFieldArray *)(buffer->data + buffer->length);
    obj->field.id = fid;
    obj->field.type = sf_serialize_value_type_int64_array;
    long2buff(count, obj->value.count);
    end = array + count;
    for (pn=array, ps=obj->value.ptr; pn<end; pn++, ps+=8) {
        int2buff(*pn, ps);
    }
    buffer->length += length;
    return 0;
}

static inline int sf_serialize_pack_map(FastBuffer *buffer,
        const unsigned char fid, const key_value_pair_t *kv_pairs,
        const int count)
{
    int result;
    int length;
    SFSerializePackFieldArray *obj;
    const key_value_pair_t *pair;
    const key_value_pair_t *end;
    SFSerializePackStringValue *ps;

    length = sizeof(SFSerializePackFieldArray);
    end = kv_pairs + count;
    for (pair=kv_pairs; pair<end; pair++) {
        length += sizeof(SFSerializePackStringValue) * 2 +
            pair->key.len + pair->value.len;
    }

    if ((result=fast_buffer_check_inc_size(buffer, length)) != 0) {
        return result;
    }

    obj = (SFSerializePackFieldArray *)(buffer->data + buffer->length);
    obj->field.id = fid;
    obj->field.type = sf_serialize_value_type_map;
    long2buff(count, obj->value.count);

    ps = (SFSerializePackStringValue *)obj->value.ptr;
    for (pair=kv_pairs; pair<end; pair++) {
        SF_SERIALIZE_PACK_STRING_AND_MOVE_PTR(ps, &pair->key);
        SF_SERIALIZE_PACK_STRING_AND_MOVE_PTR(ps, &pair->value);
    }
    buffer->length += length;
    return 0;
}

static inline void sf_serialize_pack_end(FastBuffer *buffer)
{
    SFSerializePackHeader *header;
    int length;
    int crc32;

    header = (SFSerializePackHeader *)buffer->data;
    length = buffer->length - sizeof(SFSerializePackHeader);
    crc32 = CRC32(header + 1, length);
    int2buff(length, header->length);
    int2buff(crc32, header->crc32);
}

static inline void sf_serialize_iterator_init(SFSerializeIterator *it)
{
    memset(it, 0, sizeof(SFSerializeIterator));
}

static inline void sf_serialize_iterator_destroy(SFSerializeIterator *it)
{
    if (it->int_array.elts != NULL) {
        free(it->int_array.elts);
        it->int_array_alloc = 0;
    }

    if (it->kv_array.kv_pairs != NULL) {
        free(it->kv_array.kv_pairs);
        it->kv_array_alloc = 0;
    }
}

int sf_serialize_unpack(SFSerializeIterator *it, const string_t *content);

const SFSerializeFieldValue *sf_serialize_next(SFSerializeIterator *it);

#ifdef __cplusplus
}
#endif

#endif
