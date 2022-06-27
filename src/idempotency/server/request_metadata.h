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


#ifndef _SF_IDEMPOTENCY_REQUEST_METADATA_H
#define _SF_IDEMPOTENCY_REQUEST_METADATA_H

#include "server_types.h"

typedef bool (*sf_is_master_callback)(void *arg, int64_t *data_version);

typedef struct idempotency_request_metadata {
    int64_t req_id;
    int64_t data_version;
    volatile int result;
    volatile int reffer_count;
    struct idempotency_request_metadata *next;
} IdempotencyRequestMetadata;

typedef struct idempotency_request_metadata_context {
    struct {
        sf_is_master_callback func;
        void *arg;
    } is_master_callback;
    struct fast_mblock_man allocator;  //element: IdempotencyRequestMetadata
    pthread_mutex_t lock;
    struct {
        IdempotencyRequestMetadata *head;
        IdempotencyRequestMetadata *tail;
    } list;
    struct idempotency_request_metadata_context *next;
} IdempotencyRequestMetadataContext;

#ifdef __cplusplus
extern "C" {
#endif

    int idempotency_request_metadata_init(
            IdempotencyRequestMetadataContext *ctx,
            sf_is_master_callback is_master_callback, void *arg);

    int idempotency_request_metadata_start();

    IdempotencyRequestMetadata *idempotency_request_metadata_add(
            IdempotencyRequestMetadataContext *ctx,
            SFRequestMetadata *metadata);

    int idempotency_request_metadata_get(
            IdempotencyRequestMetadataContext *ctx,
            const int64_t req_id, int *err_no);

#ifdef __cplusplus
}
#endif

#endif
