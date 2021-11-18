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

//sf_serializer.h

#ifndef _SF_SERIALIZER_H
#define _SF_SERIALIZER_H

#include "fastcommon/common_define.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/fast_buffer.h"
#include "fastcommon/hash.h"

#define SF_SERIALIZER_VALUE_TYPE_COUNT  12

typedef enum {
    sf_serializer_value_type_int8 = 0,
    sf_serializer_value_type_int16,
    sf_serializer_value_type_int32,
    sf_serializer_value_type_int64,
    sf_serializer_value_type_string,
    sf_serializer_value_type_int8_array,
    sf_serializer_value_type_int16_array,
    sf_serializer_value_type_int32_array,
    sf_serializer_value_type_int64_array,
    sf_serializer_value_type_string_array,
    sf_serializer_value_type_id_name_array,
    sf_serializer_value_type_map
} SFSerializerValueType;

typedef struct sf_serializer_pack_header {
    char length[4];
    char crc32[4];
} SFSerializerPackHeader;

typedef struct sf_serializer_pack_field_info {
    unsigned char id;
    unsigned char type;
} SFSerializerPackFieldInfo;

typedef struct sf_serializer_pack_field_int8 {
    SFSerializerPackFieldInfo field;
    char value;
} SFSerializerPackFieldInt8;

typedef struct sf_serializer_pack_field_int16 {
    SFSerializerPackFieldInfo field;
    char value[2];
} SFSerializerPackFieldInt16;

typedef struct sf_serializer_pack_field_int32 {
    SFSerializerPackFieldInfo field;
    char value[4];
} SFSerializerPackFieldInt32;

typedef struct sf_serializer_pack_field_int64 {
    SFSerializerPackFieldInfo field;
    char value[8];
} SFSerializerPackFieldInt64;

typedef struct sf_serializer_pack_string_value {
    char len[4];
    char str[0];
} SFSerializerPackStringValue;

typedef struct sf_serializer_pack_field_string {
    SFSerializerPackFieldInfo field;
    SFSerializerPackStringValue value;
} SFSerializerPackFieldString;

typedef struct sf_serializer_pack_field_array {
    SFSerializerPackFieldInfo field;
    struct {
        char count[4];
        char ptr[0];
    } value;
} SFSerializerPackFieldArray;

typedef struct sf_serializer_field_value {
    unsigned char fid;
    SFSerializerValueType type;
    union {
        int64_t n;
        string_t s;
        int64_array_t int_array;
        string_array_t str_array;
        id_name_array_t id_name_array;
        key_value_array_t kv_array;
    } value;
} SFSerializerFieldValue;

typedef struct sf_serializer_iterator {
    const char *p;
    const char *end;
    int64_array_t int_array;       //int64_t array holder
    string_array_t str_array;      //string_t array holder
    id_name_array_t id_name_array; //id name array holder
    key_value_array_t kv_array;    //key value array holder
    int int_array_alloc;
    int str_array_alloc;
    int id_name_array_alloc;
    int kv_array_alloc;
    SFSerializerFieldValue field;
    int error_no;
    char error_info[256];
} SFSerializerIterator;

#ifdef __cplusplus
extern "C" {
#endif

static inline void sf_serializer_pack_begin(FastBuffer *buffer)
{
    buffer->length = sizeof(SFSerializerPackHeader);
}

static inline int sf_serializer_pack_int8(FastBuffer *buffer,
        const unsigned char fid, const int8_t value)
{
    int result;
    SFSerializerPackFieldInt8 *obj;

    if ((result=fast_buffer_check_inc_size(buffer,
                    sizeof(SFSerializerPackFieldInt8))) != 0)
    {
        return result;
    }

    obj = (SFSerializerPackFieldInt8 *)(buffer->data + buffer->length);
    obj->field.id = fid;
    obj->field.type = sf_serializer_value_type_int8;
    obj->value = value;
    buffer->length += sizeof(SFSerializerPackFieldInt8);
    return 0;
}

static inline int sf_serializer_pack_int16(FastBuffer *buffer,
        const unsigned char fid, const int16_t value)
{
    int result;
    SFSerializerPackFieldInt16 *obj;

    if ((result=fast_buffer_check_inc_size(buffer,
                    sizeof(SFSerializerPackFieldInt16))) != 0)
    {
        return result;
    }

    obj = (SFSerializerPackFieldInt16 *)(buffer->data + buffer->length);
    obj->field.id = fid;
    obj->field.type = sf_serializer_value_type_int16;
    short2buff(value, obj->value);
    buffer->length += sizeof(SFSerializerPackFieldInt16);
    return 0;
}

static inline int sf_serializer_pack_int32(FastBuffer *buffer,
        const unsigned char fid, const int32_t value)
{
    int result;
    SFSerializerPackFieldInt32 *obj;

    if ((result=fast_buffer_check_inc_size(buffer,
                    sizeof(SFSerializerPackFieldInt32))) != 0)
    {
        return result;
    }

    obj = (SFSerializerPackFieldInt32 *)(buffer->data + buffer->length);
    obj->field.id = fid;
    obj->field.type = sf_serializer_value_type_int32;
    int2buff(value, obj->value);
    buffer->length += sizeof(SFSerializerPackFieldInt32);
    return 0;
}

static inline int sf_serializer_pack_int64(FastBuffer *buffer,
        const unsigned char fid, const int64_t value)
{
    int result;
    SFSerializerPackFieldInt64 *obj;

    if ((result=fast_buffer_check_inc_size(buffer,
                    sizeof(SFSerializerPackFieldInt64))) != 0)
    {
        return result;
    }

    obj = (SFSerializerPackFieldInt64 *)(buffer->data + buffer->length);
    obj->field.id = fid;
    obj->field.type = sf_serializer_value_type_int64;
    long2buff(value, obj->value);
    buffer->length += sizeof(SFSerializerPackFieldInt64);
    return 0;
}

static inline int sf_serializer_pack_integer(FastBuffer *buffer,
        const unsigned char fid, const int64_t value)
{
    if (value >= INT16_MIN && value <= INT16_MAX) {
        if (value >= INT8_MIN && value <= INT8_MAX) {
            return sf_serializer_pack_int8(buffer, fid, value);
        } else {
            return sf_serializer_pack_int16(buffer, fid, value);
        }
    } else {
        if (value >= INT32_MIN && value <= INT32_MAX) {
            return sf_serializer_pack_int32(buffer, fid, value);
        } else {
            return sf_serializer_pack_int64(buffer, fid, value);
        }
    }
}

#define SF_SERIALIZER_PACK_STRING(ps, value)  \
    int2buff((value)->len, (ps)->len);   \
    memcpy((ps)->str, (value)->str, (value)->len)

#define SF_SERIALIZER_PACK_STRING_AND_MOVE_PTR(p, value)  \
    SF_SERIALIZER_PACK_STRING((SFSerializerPackStringValue *)p, value); \
    p += (sizeof(SFSerializerPackStringValue) + (value)->len)

static inline int sf_serializer_pack_string(FastBuffer *buffer,
        const unsigned char fid, const string_t *value)
{
    int result;
    int length;
    SFSerializerPackFieldString *obj;

    length = sizeof(SFSerializerPackFieldString) + value->len;
    if ((result=fast_buffer_check_inc_size(buffer, length)) != 0) {
        return result;
    }

    obj = (SFSerializerPackFieldString *)(buffer->data + buffer->length);
    obj->field.id = fid;
    obj->field.type = sf_serializer_value_type_string;
    SF_SERIALIZER_PACK_STRING(&obj->value, value);
    buffer->length += length;
    return 0;
}

static inline int sf_serializer_pack_buffer(FastBuffer *buffer,
        const unsigned char fid, const FastBuffer *value)
{
    string_t str;
    FC_SET_STRING_EX(str, value->data, value->length);
    return sf_serializer_pack_string(buffer, fid, &str);
}

static inline int sf_serializer_pack_int8_array(FastBuffer *buffer,
        const unsigned char fid, const int8_t *array, const int count)
{
    int result;
    int length;
    SFSerializerPackFieldArray *obj;
    const int8_t *pn;
    const int8_t *end;
    char *ps;

    length = sizeof(SFSerializerPackFieldArray) + count * 1;
    if ((result=fast_buffer_check_inc_size(buffer, length)) != 0) {
        return result;
    }

    obj = (SFSerializerPackFieldArray *)(buffer->data + buffer->length);
    obj->field.id = fid;
    obj->field.type = sf_serializer_value_type_int8_array;
    int2buff(count, obj->value.count);
    end = array + count;
    for (pn=array, ps=obj->value.ptr; pn<end; pn++) {
        *ps++ = *pn;
    }
    buffer->length += length;
    return 0;
}

static inline int sf_serializer_pack_int16_array(FastBuffer *buffer,
        const unsigned char fid, const int16_t *array, const int count)
{
    int result;
    int length;
    SFSerializerPackFieldArray *obj;
    const int16_t *pn;
    const int16_t *end;
    char *ps;

    length = sizeof(SFSerializerPackFieldArray) + count * 2;
    if ((result=fast_buffer_check_inc_size(buffer, length)) != 0) {
        return result;
    }

    obj = (SFSerializerPackFieldArray *)(buffer->data + buffer->length);
    obj->field.id = fid;
    obj->field.type = sf_serializer_value_type_int16_array;
    int2buff(count, obj->value.count);
    end = array + count;
    for (pn=array, ps=obj->value.ptr; pn<end; pn++, ps+=2) {
        short2buff(*pn, ps);
    }
    buffer->length += length;
    return 0;
}

static inline int sf_serializer_pack_int32_array(FastBuffer *buffer,
        const unsigned char fid, const int32_t *array, const int count)
{
    int result;
    int length;
    SFSerializerPackFieldArray *obj;
    const int32_t *pn;
    const int32_t *end;
    char *ps;

    length = sizeof(SFSerializerPackFieldArray) + count * 4;
    if ((result=fast_buffer_check_inc_size(buffer, length)) != 0) {
        return result;
    }

    obj = (SFSerializerPackFieldArray *)(buffer->data + buffer->length);
    obj->field.id = fid;
    obj->field.type = sf_serializer_value_type_int32_array;
    int2buff(count, obj->value.count);
    end = array + count;
    for (pn=array, ps=obj->value.ptr; pn<end; pn++, ps+=4) {
        int2buff(*pn, ps);
    }
    buffer->length += length;
    return 0;
}

static inline int sf_serializer_pack_int64_array(FastBuffer *buffer,
        const unsigned char fid, const int64_t *array, const int count)
{
    int result;
    int length;
    SFSerializerPackFieldArray *obj;
    const int64_t *pn;
    const int64_t *end;
    char *ps;

    length = sizeof(SFSerializerPackFieldArray) + count * 8;
    if ((result=fast_buffer_check_inc_size(buffer, length)) != 0) {
        return result;
    }

    obj = (SFSerializerPackFieldArray *)(buffer->data + buffer->length);
    obj->field.id = fid;
    obj->field.type = sf_serializer_value_type_int64_array;
    int2buff(count, obj->value.count);
    end = array + count;
    for (pn=array, ps=obj->value.ptr; pn<end; pn++, ps+=8) {
        long2buff(*pn, ps);
    }
    buffer->length += length;
    return 0;
}

static inline int sf_serializer_pack_string_array(FastBuffer *buffer,
        const unsigned char fid, const string_t *strings, const int count)
{
    int result;
    int length;
    SFSerializerPackFieldArray *obj;
    const string_t *str;
    const string_t *end;
    char *p;

    length = sizeof(SFSerializerPackFieldArray);
    end = strings + count;
    for (str=strings; str<end; str++) {
        length += sizeof(SFSerializerPackStringValue) + str->len;
    }

    if ((result=fast_buffer_check_inc_size(buffer, length)) != 0) {
        return result;
    }

    obj = (SFSerializerPackFieldArray *)(buffer->data + buffer->length);
    obj->field.id = fid;
    obj->field.type = sf_serializer_value_type_string_array;
    int2buff(count, obj->value.count);

    p = obj->value.ptr;
    for (str=strings; str<end; str++) {
        SF_SERIALIZER_PACK_STRING_AND_MOVE_PTR(p, str);
    }
    buffer->length += length;
    return 0;
}

static inline int sf_serializer_pack_id_name_array(FastBuffer *buffer,
        const unsigned char fid, const id_name_pair_t *in_pairs,
        const int count)
{
    int result;
    int length;
    SFSerializerPackFieldArray *obj;
    const id_name_pair_t *pair;
    const id_name_pair_t *end;
    char *p;

    length = sizeof(SFSerializerPackFieldArray);
    end = in_pairs + count;
    for (pair=in_pairs; pair<end; pair++) {
        length += sizeof(int64_t) + pair->name.len +
            sizeof(SFSerializerPackStringValue);
    }

    if ((result=fast_buffer_check_inc_size(buffer, length)) != 0) {
        return result;
    }

    obj = (SFSerializerPackFieldArray *)(buffer->data + buffer->length);
    obj->field.id = fid;
    obj->field.type = sf_serializer_value_type_id_name_array;
    int2buff(count, obj->value.count);

    p = obj->value.ptr;
    for (pair=in_pairs; pair<end; pair++) {
        long2buff(pair->id, p);
        p += sizeof(int64_t);
        SF_SERIALIZER_PACK_STRING_AND_MOVE_PTR(p, &pair->name);
    }
    buffer->length += length;
    return 0;
}

static inline int sf_serializer_pack_map(FastBuffer *buffer,
        const unsigned char fid, const key_value_pair_t *kv_pairs,
        const int count)
{
    int result;
    int length;
    SFSerializerPackFieldArray *obj;
    const key_value_pair_t *pair;
    const key_value_pair_t *end;
    char *p;

    length = sizeof(SFSerializerPackFieldArray);
    end = kv_pairs + count;
    for (pair=kv_pairs; pair<end; pair++) {
        length += sizeof(SFSerializerPackStringValue) * 2 +
            pair->key.len + pair->value.len;
    }

    if ((result=fast_buffer_check_inc_size(buffer, length)) != 0) {
        return result;
    }

    obj = (SFSerializerPackFieldArray *)(buffer->data + buffer->length);
    obj->field.id = fid;
    obj->field.type = sf_serializer_value_type_map;
    int2buff(count, obj->value.count);

    p = obj->value.ptr;
    for (pair=kv_pairs; pair<end; pair++) {
        SF_SERIALIZER_PACK_STRING_AND_MOVE_PTR(p, &pair->key);
        SF_SERIALIZER_PACK_STRING_AND_MOVE_PTR(p, &pair->value);
    }
    buffer->length += length;
    return 0;
}

static inline void sf_serializer_pack_end(FastBuffer *buffer)
{
    SFSerializerPackHeader *header;
    int length;
    int crc32;

    header = (SFSerializerPackHeader *)buffer->data;
    length = buffer->length - sizeof(SFSerializerPackHeader);
    crc32 = CRC32(header + 1, length);
    int2buff(length, header->length);
    int2buff(crc32, header->crc32);
}

static inline void sf_serializer_iterator_init(SFSerializerIterator *it)
{
    memset(it, 0, sizeof(SFSerializerIterator));
}

static inline void sf_serializer_iterator_destroy(SFSerializerIterator *it)
{
    if (it->int_array.elts != NULL) {
        free(it->int_array.elts);
        it->int_array_alloc = 0;
    }

    if (it->kv_array.kv_pairs != NULL) {
        free(it->kv_array.kv_pairs);
        it->kv_array_alloc = 0;
    }

    if (it->str_array.strings != NULL) {
        free(it->str_array.strings);
        it->str_array_alloc = 0;
    }
}

int sf_serializer_unpack(SFSerializerIterator *it, const string_t *content);

const SFSerializerFieldValue *sf_serializer_next(SFSerializerIterator *it);

int sf_serializer_read_message(int fd, BufferInfo *buffer,
        const int max_size);

#ifdef __cplusplus
}
#endif

#endif
