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


#ifndef _IDEMPOTENCY_CLIENT_TYPES_H
#define _IDEMPOTENCY_CLIENT_TYPES_H

#include "fastcommon/fast_task_queue.h"
#include "fastcommon/fast_mblock.h"
#include "fastcommon/fc_list.h"
#include "fastcommon/fc_queue.h"

typedef struct idempotency_client_config {
    bool enabled;
    int channel_htable_capacity;
    int channel_heartbeat_interval;
    int channel_max_idle_time;
} IdempotencyClientConfig;

typedef struct idempotency_client_receipt {
    uint64_t req_id;
    struct idempotency_client_receipt *next;
} IdempotencyClientReceipt;

typedef struct idempotency_client_channel {
    volatile uint32_t id;  //channel id, 0 for invalid
    volatile int key;      //channel key
    volatile char in_ioevent;
    volatile char established;
    int buffer_size;  //the min task size of the server and mine
    time_t last_connect_time;  //for connect frequency control
    time_t last_pkg_time;      //last communication time
    time_t last_report_time;   //last report time for rpc receipt
    pthread_lock_cond_pair_t lc_pair;  //for channel valid check and notify
    volatile uint64_t next_req_id;
    struct fast_mblock_man receipt_allocator;
    struct fast_task_info *task;
    struct fc_queue queue;
    struct fc_queue_info waiting_resp_qinfo;
    struct fc_list_head dlink;  //LRU chain for heartbeat
    struct idempotency_client_channel *next;
} IdempotencyClientChannel;

typedef struct idempotency_receipt_thread_context {
    struct fc_list_head head;  //LRU head for hearbeat
    struct {
        time_t heartbeat;
        time_t idle;
    } last_check_times;
} IdempotencyReceiptThreadContext;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif
