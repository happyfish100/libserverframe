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

//sf_service.h

#ifndef _SF_SERVICE_H_
#define _SF_SERVICE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "fastcommon/ioevent.h"
#include "fastcommon/fast_task_queue.h"
#include "sf_types.h"

typedef void* (*sf_alloc_thread_extra_data_callback)(const int thread_index);
typedef void (*sf_sig_quit_handler)(int sig);

#ifdef __cplusplus
extern "C" {
#endif

int sf_service_init_ex2(SFContext *sf_context,
        sf_alloc_thread_extra_data_callback
        alloc_thread_extra_data_callback,
        ThreadLoopCallback thread_loop_callback,
        sf_accept_done_callback accept_done_callback,
        sf_set_body_length_callback set_body_length_func,
        sf_deal_task_func deal_func, TaskCleanUpCallback task_cleanup_func,
        sf_recv_timeout_callback timeout_callback, const int net_timeout_ms,
        const int proto_header_size, const int task_arg_size,
        TaskInitCallback init_callback);

#define sf_service_init_ex(sf_context, alloc_thread_extra_data_callback,  \
        thread_loop_callback, accept_done_callback, set_body_length_func, \
        deal_func, task_cleanup_func, timeout_callback, net_timeout_ms,   \
        proto_header_size, task_arg_size) \
    sf_service_init_ex2(sf_context, alloc_thread_extra_data_callback,     \
        thread_loop_callback, accept_done_callback, set_body_length_func, \
        deal_func, task_cleanup_func, timeout_callback, net_timeout_ms,   \
        proto_header_size, task_arg_size, NULL)

#define sf_service_init(alloc_thread_extra_data_callback, \
        thread_loop_callback, accept_done_callback, set_body_length_func, \
        deal_func, task_cleanup_func, timeout_callback, net_timeout_ms,   \
        proto_header_size, task_arg_size) \
    sf_service_init_ex2(&g_sf_context, alloc_thread_extra_data_callback,  \
        thread_loop_callback, accept_done_callback, set_body_length_func, \
        deal_func, task_cleanup_func, timeout_callback, net_timeout_ms,   \
        proto_header_size, task_arg_size, NULL)

int sf_service_destroy_ex(SFContext *sf_context);

#define sf_service_destroy() sf_service_destroy_ex(&g_sf_context)

int sf_setup_signal_handler();
int sf_startup_schedule(pthread_t *schedule_tid);
void sf_set_current_time();

int sf_socket_server_ex(SFContext *sf_context);
#define sf_socket_server() sf_socket_server_ex(&g_sf_context)

void sf_accept_loop_ex(SFContext *sf_context, const bool block);

#define sf_accept_loop()  sf_accept_loop_ex(&g_sf_context, true)

void sf_enable_thread_notify_ex(SFContext *sf_context, const bool enabled);

#define sf_enable_thread_notify(enabled)  \
    sf_enable_thread_notify_ex(&g_sf_context, enabled)

static inline void sf_enable_realloc_task_buffer_ex(SFContext *sf_context,
        const bool enabled)
{
    sf_context->realloc_task_buffer = enabled;
}

#define sf_enable_realloc_task_buffer(enabled)  \
    sf_enable_realloc_task_buffer_ex(&g_sf_context, enabled)

struct nio_thread_data *sf_get_random_thread_data_ex(SFContext *sf_context);

#define sf_get_random_thread_data()  \
    sf_get_random_thread_data_ex(&g_sf_context)

void sf_set_sig_quit_handler(sf_sig_quit_handler quit_handler);

int sf_init_task(struct fast_task_info *task);

#ifdef __cplusplus
}
#endif

#endif
