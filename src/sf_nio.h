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

//sf_nio.h

#ifndef _SF_NIO_H
#define _SF_NIO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fastcommon/fast_task_queue.h"
#include "sf_define.h"
#include "sf_types.h"

#ifdef __cplusplus
extern "C" {
#endif

void sf_set_parameters_ex(SFContext *sf_context, const int header_size,
        sf_set_body_length_callback set_body_length_func,
        sf_deal_task_func deal_func, TaskCleanUpCallback cleanup_func,
        sf_recv_timeout_callback timeout_callback, sf_release_buffer_callback
        release_buffer_callback);

#define sf_set_parameters(header_size, set_body_length_func, \
        deal_func, cleanup_func, timeout_callback)   \
    sf_set_parameters_ex(&g_sf_context, header_size, \
            set_body_length_func, deal_func, \
            cleanup_func, timeout_callback, NULL)

static inline void sf_set_deal_task_func_ex(SFContext *sf_context,
        sf_deal_task_func deal_func)
{
    sf_context->deal_task = deal_func;
}

#define sf_set_deal_task_func(deal_func) \
    sf_set_deal_task_func_ex(&g_sf_context, deal_func)

static inline void sf_set_remove_from_ready_list_ex(SFContext *sf_context,
        const bool enabled)
{
    sf_context->remove_from_ready_list = enabled;
}

#define sf_set_remove_from_ready_list(enabled) \
    sf_set_remove_from_ready_list_ex(&g_sf_context, enabled);

static inline TaskCleanUpCallback sf_get_task_cleanup_func_ex(
        SFContext *sf_context)
{
    return sf_context->task_cleanup_func;
}

#define sf_get_task_cleanup_func() \
    sf_get_task_cleanup_func_ex(&g_sf_context)

#define sf_nio_task_is_idle(task) \
    (task->offset == 0 && task->length == 0)

void sf_recv_notify_read(int sock, short event, void *arg);
int sf_send_add_event(struct fast_task_info *task);
int sf_client_sock_write(int sock, short event, void *arg);
int sf_client_sock_read(int sock, short event, void *arg);

void sf_task_finish_clean_up(struct fast_task_info *task);

int sf_nio_notify(struct fast_task_info *task, const int stage);

int sf_set_read_event(struct fast_task_info *task);

void sf_task_switch_thread(struct fast_task_info *task,
        const int new_thread_index);

void sf_task_detach_thread(struct fast_task_info *task);

static inline int sf_nio_forward_request(struct fast_task_info *task,
        const int new_thread_index)
{
    sf_task_switch_thread(task, new_thread_index);
    return sf_nio_notify(task, SF_NIO_STAGE_FORWARDED);
}

static inline bool sf_client_sock_in_read_stage(struct fast_task_info *task)
{
    return (task->event.callback == (IOEventCallback)sf_client_sock_read);
}

#ifdef __cplusplus
}
#endif

#endif
