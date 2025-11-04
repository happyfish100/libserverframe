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
#include "sf_proto.h"
#include "sf_global.h"
#include "sf_nio.h"

typedef void* (*sf_alloc_thread_extra_data_callback)(const int thread_index);
typedef void (*sf_sig_quit_handler)(int sig);

#ifdef __cplusplus
extern "C" {
#endif

int sf_service_init_ex2(SFContext *sf_context, const char *name,
        sf_alloc_thread_extra_data_callback
        alloc_thread_extra_data_callback,
        ThreadLoopCallback thread_loop_callback,
        sf_accept_done_callback accept_done_callback,
        sf_set_body_length_callback set_body_length_func,
        sf_alloc_recv_buffer_callback alloc_recv_buffer_func,
        sf_send_done_callback send_done_callback,
        sf_deal_task_callback deal_func, TaskCleanUpCallback task_cleanup_func,
        sf_recv_timeout_callback timeout_callback, const int net_timeout_ms,
        const int proto_header_size, const int task_padding_size,
        const int task_arg_size, const bool double_buffers,
        const bool need_shrink_task_buffer, const bool explicit_post_recv,
        TaskInitCallback init_callback, void *init_arg,
        sf_release_buffer_callback release_buffer_callback);

#define sf_service_init_ex(sf_context, name, alloc_thread_extra_data_callback,\
        thread_loop_callback, accept_done_callback, set_body_length_func,   \
        send_done_callback, deal_func, task_cleanup_func, timeout_callback, \
        net_timeout_ms, proto_header_size, task_arg_size) \
    sf_service_init_ex2(sf_context, name, alloc_thread_extra_data_callback,   \
        thread_loop_callback, accept_done_callback, set_body_length_func,     \
        NULL, send_done_callback, deal_func, task_cleanup_func, \
        timeout_callback, net_timeout_ms, proto_header_size, \
        0, task_arg_size, false, true, false, NULL, NULL, NULL)

#define sf_service_init(name, alloc_thread_extra_data_callback, \
        thread_loop_callback, accept_done_callback, set_body_length_func,   \
        send_done_callback, deal_func, task_cleanup_func, timeout_callback, \
        net_timeout_ms, proto_header_size, task_arg_size) \
    sf_service_init_ex2(&g_sf_context, name, alloc_thread_extra_data_callback, \
        thread_loop_callback, accept_done_callback, set_body_length_func, NULL,\
        send_done_callback, deal_func, task_cleanup_func, timeout_callback, \
        net_timeout_ms, proto_header_size, 0, task_arg_size, false, true,   \
        false, NULL, NULL, NULL)

int sf_service_destroy_ex(SFContext *sf_context);

#define sf_service_destroy() sf_service_destroy_ex(&g_sf_context)

void sf_service_set_thread_loop_callback_ex(SFContext *sf_context,
        ThreadLoopCallback thread_loop_callback);

#define sf_service_set_thread_loop_callback(thread_loop_callback) \
    sf_service_set_thread_loop_callback_ex(&g_sf_context, thread_loop_callback)

static inline void sf_service_set_smart_polling_ex(SFContext *sf_context,
        const FCSmartPollingConfig *smart_polling)
{
    sf_context->smart_polling = *smart_polling;
}
#define sf_service_set_smart_polling(smart_polling) \
    sf_service_set_smart_polling_ex(&g_sf_context, smart_polling)

static inline void sf_service_set_connect_need_log_ex(
        SFContext *sf_context, const bool need_log)
{
    sf_context->connect_need_log = need_log;
}
#define sf_service_set_connect_need_log(need_log) \
    sf_service_set_connect_need_log_ex(&g_sf_context, need_log)


int sf_setup_signal_handler();

int sf_startup_schedule(pthread_t *schedule_tid);
int sf_add_slow_log_schedule(SFSlowLogContext *slowlog_ctx);

void sf_set_current_time();
int sf_global_init(const char *log_filename_prefix);

int sf_socket_create_server(SFListener *listener,
        int af, const char *bind_addr);
void sf_socket_close_server(SFListener *listener);
struct fast_task_info *sf_socket_accept_connection(SFListener *listener);

int sf_socket_server_ex(SFContext *sf_context);
#define sf_socket_server() sf_socket_server_ex(&g_sf_context)

void sf_socket_close_ex(SFContext *sf_context);
#define sf_socket_close() sf_socket_close_ex(&g_sf_context)

int sf_accept_loop_ex(SFContext *sf_context, const bool blocked);

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


void sf_notify_all_threads_ex(SFContext *sf_context);

#define sf_notify_all_threads()  \
    sf_notify_all_threads_ex(&g_sf_context)


void sf_set_sig_quit_handler(sf_sig_quit_handler quit_handler);

static inline struct fast_task_info *sf_alloc_init_task_ex(
        SFNetworkHandler *handler, const int fd,
        const int reffer_count)
{
    struct fast_task_info *task;

    task = free_queue_pop(&handler->fh->ctx->free_queue);
    if (task == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc task buff failed, you should "
                "increase the parameter: max_connections",
                __LINE__);
        return NULL;
    }

    if (task->shrinked) {
        task->shrinked = false;
        sf_proto_init_task_magic(task);
    }

    __sync_add_and_fetch(&task->reffer_count, reffer_count);
    __sync_bool_compare_and_swap(&task->canceled, 1, 0);
    task->handler = handler;
    task->event.fd = fd;
    return task;
}

#define sf_hold_task_ex(task, inc_count)  fc_hold_task_ex(task, inc_count)
#define sf_hold_task(task)  fc_hold_task(task)

#define sf_alloc_init_task(handler, fd) sf_alloc_init_task_ex(handler, fd, 1)

static inline struct fast_task_info *sf_alloc_init_server_task(
        SFNetworkHandler *handler, const int fd)
{
    const int reffer_count = 1;
    struct fast_task_info *task;

    if ((task=sf_alloc_init_task_ex(handler, fd, reffer_count)) != NULL) {
#if IOEVENT_USE_URING
        FC_URING_IS_CLIENT(task) = false;
#endif
    }

    return task;
}

static inline struct fast_task_info *sf_alloc_init_client_task(
        SFNetworkHandler *handler)
{
    const int fd = -1;
    const int reffer_count = 1;
    struct fast_task_info *task;

    if ((task=sf_alloc_init_task_ex(handler, fd, reffer_count)) != NULL) {
#if IOEVENT_USE_URING
        FC_URING_IS_CLIENT(task) = true;
#endif
    }

    return task;
}

static inline void sf_release_task(struct fast_task_info *task)
{
    if (__sync_sub_and_fetch(&task->reffer_count, 1) == 0) {
        /*
        int free_count = free_queue_count();
        int alloc_count = free_queue_alloc_connections();
        logInfo("file: "__FILE__", line: %d, "
                "push task %p to queue, alloc: %d, "
                "used: %d, freed: %d", __LINE__, task,
                alloc_count, alloc_count - free_count, free_count);
                */

#if IOEVENT_USE_URING
        if (SF_CTX->use_io_uring) {
            task->handler->close_connection(task);
            __sync_fetch_and_sub(&g_sf_global_vars.
                    connection_stat.current_count, 1);
        }
#endif

        free_queue_push(task);
    }
}

static inline SFNetworkHandler *sf_get_first_network_handler_ex(
        SFContext *sf_context)
{
    int i;
    SFNetworkHandler *handler;
    SFNetworkHandler *end;

    for (i=0; i<SF_ADDRESS_FAMILY_COUNT; i++) {
        if (sf_context->handlers[i].af == AF_UNSPEC) {
            continue;
        }

        end = sf_context->handlers[i].handlers + SF_NETWORK_HANDLER_COUNT;
        for (handler=sf_context->handlers[i].handlers; handler<end; handler++) {
            if (handler->enabled) {
                return handler;
            }
        }
    }

    return NULL;
}
#define sf_get_first_network_handler() \
    sf_get_first_network_handler_ex(&g_sf_context)


static inline SFNetworkHandler *sf_get_rdma_network_handler(
        SFContext *sf_context)
{
    int i;
    SFNetworkHandler *handler;

    for (i=0; i<SF_ADDRESS_FAMILY_COUNT; i++) {
        if (sf_context->handlers[i].af != AF_UNSPEC) {
            handler = sf_context->handlers[i].handlers +
                SF_RDMACM_NETWORK_HANDLER_INDEX;
            if (handler->enabled) {
                return handler;
            }
        }
    }

    return NULL;
}

static inline SFNetworkHandler *sf_get_rdma_network_handler2(
        SFContext *sf_context1, SFContext *sf_context2)
{
    SFNetworkHandler *handler;

    if ((handler=sf_get_rdma_network_handler(sf_context1)) != NULL) {
        return handler;
    }
    return sf_get_rdma_network_handler(sf_context2);
}

static inline SFNetworkHandler *sf_get_rdma_network_handler3(
        SFContext *sf_context1, SFContext *sf_context2,
        SFContext *sf_context3)
{
    SFNetworkHandler *handler;

    if ((handler=sf_get_rdma_network_handler(sf_context1)) != NULL) {
        return handler;
    }
    if ((handler=sf_get_rdma_network_handler(sf_context2)) != NULL) {
        return handler;
    }
    return sf_get_rdma_network_handler(sf_context3);
}

static inline bool sf_get_double_buffers_flag(FCServerGroupInfo *server_group)
{
    if (server_group->comm_type == fc_comm_type_sock) {
#if IOEVENT_USE_URING
        return true;
#else
        return false;
#endif
    } else {  //RDMA
        return true;
    }
}

#ifdef __cplusplus
}
#endif

#endif
