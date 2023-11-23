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
#include "fastcommon/ioevent_loop.h"
#include "sf_define.h"
#include "sf_types.h"
#include "sf_global.h"

#define SF_CTX  (task->handler->ctx)

#ifdef __cplusplus
extern "C" {
#endif

void sf_set_parameters_ex(SFContext *sf_context, const int header_size,
        sf_set_body_length_callback set_body_length_func,
        sf_alloc_recv_buffer_callback alloc_recv_buffer_func,
        sf_send_done_callback send_done_callback,
        sf_deal_task_callback deal_func, TaskCleanUpCallback cleanup_func,
        sf_recv_timeout_callback timeout_callback, sf_release_buffer_callback
        release_buffer_callback);

#define sf_set_parameters(header_size, set_body_length_func, \
        alloc_recv_buffer_func, deal_func, cleanup_func, timeout_callback) \
    sf_set_parameters_ex(&g_sf_context, header_size, \
            set_body_length_func, alloc_recv_buffer_func, \
            deal_func, cleanup_func, timeout_callback, NULL)

static inline void sf_set_deal_task_callback_ex(SFContext *sf_context,
        sf_deal_task_callback deal_func)
{
    sf_context->callbacks.deal_task = deal_func;
}

#define sf_set_deal_task_callback(deal_func) \
    sf_set_deal_task_callback_ex(&g_sf_context, deal_func)


static inline void sf_set_connect_done_callback_ex(SFContext *sf_context,
        sf_connect_done_callback done_callback)
{
    sf_context->callbacks.connect_done = done_callback;
}

#define sf_set_connect_done_callback(done_callback) \
    sf_set_connect_done_callback_ex(&g_sf_context, done_callback)


static inline void sf_set_remove_from_ready_list_ex(
        SFContext *sf_context, const bool enabled)
{
    sf_context->remove_from_ready_list = enabled;
}

#define sf_set_remove_from_ready_list(enabled) \
    sf_set_remove_from_ready_list_ex(&g_sf_context, enabled);

static inline TaskCleanUpCallback sf_get_task_cleanup_callback_ex(
        SFContext *sf_context)
{
    return sf_context->callbacks.task_cleanup;
}

#define sf_get_task_cleanup_callback() \
    sf_get_task_cleanup_callback_ex(&g_sf_context)

#define sf_nio_task_send_done(task) \
    (task->send.ptr->offset == 0 && task->send.ptr->length == 0)

static inline void sf_nio_reset_task_length(struct fast_task_info *task)
{
    task->send.ptr->length = 0;
    task->send.ptr->offset = 0;
    if (task->recv.ptr != task->send.ptr) {
        task->recv.ptr->length = 0;
        task->recv.ptr->offset = 0;
    }
}

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

static inline int sf_set_body_length(struct fast_task_info *task)
{
    if (SF_CTX->callbacks.set_body_length(task) != 0) {
        return -1;
    }
    if (task->recv.ptr->length < 0) {
        logError("file: "__FILE__", line: %d, "
                "client ip: %s, pkg length: %d < 0",
                __LINE__, task->client_ip,
                task->recv.ptr->length);
        return -1;
    }

    task->recv.ptr->length += SF_CTX->header_size;
    if (task->recv.ptr->length > g_sf_global_vars.max_pkg_size) {
        logError("file: "__FILE__", line: %d, "
                "client ip: %s, pkg length: %d > "
                "max pkg size: %d", __LINE__,
                task->client_ip, task->recv.ptr->length,
                g_sf_global_vars.max_pkg_size);
        return -1;
    }

    return 0;
}

int sf_socket_async_connect_server(struct fast_task_info *task);
int sf_socket_async_connect_check(struct fast_task_info *task);

ssize_t sf_socket_send_data(struct fast_task_info *task,
        SFCommAction *action, bool *send_done);
ssize_t sf_socket_recv_data(struct fast_task_info *task,
        const bool call_post_recv, SFCommAction *action);

int sf_rdma_busy_polling_callback(struct nio_thread_data *thread_data);

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

static inline void sf_nio_add_to_deleted_list(struct nio_thread_data
        *thread_data, struct fast_task_info *task)
{
    if (task->thread_data == thread_data) {
        ioevent_add_to_deleted_list(task);
    } else {
        sf_nio_notify(task, SF_NIO_STAGE_CLOSE);
    }
}

#ifdef __cplusplus
}
#endif

#endif
