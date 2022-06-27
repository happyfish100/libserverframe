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


#ifndef _IDEMPOTENCY_SERVER_TYPES_H
#define _IDEMPOTENCY_SERVER_TYPES_H

#include "fastcommon/fast_mblock.h"
#include "fastcommon/fast_timer.h"
#include "sf/idempotency/common/idempotency_types.h"

#define SF_IDEMPOTENCY_DEFAULT_REQUEST_HINT_CAPACITY      1023
#define SF_IDEMPOTENCY_DEFAULT_CHANNEL_RESERVE_INTERVAL    600
#define SF_IDEMPOTENCY_DEFAULT_CHANNEL_SHARED_LOCK_COUNT   163

typedef struct idempotency_request_result {
    short rsize;  //response size defined by application
    short flags;  //for application
    volatile int result;
    void * volatile response;
} IdempotencyRequestResult;

typedef struct idempotency_request {
    uint64_t req_id;
    volatile int ref_count;
    volatile char finished;
    IdempotencyRequestResult output;
    struct fast_mblock_man *allocator;  //for free
    struct idempotency_request *next;
} IdempotencyRequest;

typedef struct idempotency_request_htable {
    IdempotencyRequest **buckets;
    int count;
    pthread_mutex_t lock;
} IdempotencyRequestHTable;

typedef struct idempotency_channel {
    FastTimerEntry timer;  //must be the first
    uint32_t id;
    int key;      //for retrieve validation
    volatile int ref_count;
    volatile char is_valid;
    IdempotencyRequestHTable request_htable;
    struct idempotency_channel *next;
} IdempotencyChannel;

typedef struct sf_request_metadata {
    int64_t req_id;
    int64_t data_version;
} SFRequestMetadata;

typedef struct sf_request_metadata_array {
    SFRequestMetadata *elts;
    int count;
    int alloc;
} SFRequestMetadataArray;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif
