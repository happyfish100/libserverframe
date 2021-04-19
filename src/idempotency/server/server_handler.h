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

//server_handler.h

#ifndef _SF_IDEMPOTENCY_SERVER_HANDLER_H
#define _SF_IDEMPOTENCY_SERVER_HANDLER_H

#include "server_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int sf_server_deal_setup_channel(struct fast_task_info *task,
        int *task_type, IdempotencyChannel **channel,
        SFResponseInfo *response);

int sf_server_deal_close_channel(struct fast_task_info *task,
        int *task_type, IdempotencyChannel **channel,
        SFResponseInfo *response);

int sf_server_deal_report_req_receipt(struct fast_task_info *task,
        const int task_type, IdempotencyChannel *channel,
        SFResponseInfo *response);

IdempotencyRequest *sf_server_update_prepare_and_check(
        SFRequestInfo *req, struct fast_mblock_man *
        request_allocator, IdempotencyChannel *channel,
        SFResponseInfo *response, int *result);

int sf_server_deal_rebind_channel(struct fast_task_info *task,
        int *server_task_type, IdempotencyChannel **channel,
        SFResponseInfo *response);

#ifdef __cplusplus
}
#endif

#endif
