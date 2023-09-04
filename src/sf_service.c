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

//sf_service.c

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "fastcommon/logger.h"
#include "fastcommon/sockopt.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/pthread_func.h"
#include "fastcommon/sched_thread.h"
#include "fastcommon/ioevent_loop.h"
#include "fastcommon/fc_memory.h"
#include "sf_nio.h"
#include "sf_util.h"
#include "sf_global.h"
#include "sf_service.h"

#if defined(OS_LINUX)
#include <sys/eventfd.h>
#endif

static bool terminate_flag = false;
static sf_sig_quit_handler sig_quit_handler = NULL;

static void sigQuitHandler(int sig);
static void sigHupHandler(int sig);
static void sigUsrHandler(int sig);

#if defined(DEBUG_FLAG)
static void sigDumpHandler(int sig);
#endif

struct worker_thread_context {
    SFContext *sf_context;
    struct nio_thread_data *thread_data;
};

int sf_init_task(struct fast_task_info *task)
{
    task->connect_timeout = SF_G_CONNECT_TIMEOUT; //for client side
    task->network_timeout = SF_G_NETWORK_TIMEOUT;
    return 0;
}

static void *worker_thread_entrance(void *arg);

static int sf_init_free_queues(const int task_arg_size,
        TaskInitCallback init_callback)
{
#define ALLOC_CONNECTIONS_ONCE 1024

    static bool sf_inited = false;
    int result;
    int m;
    int init_connections;
    int alloc_conn_once;

    if (sf_inited) {
        return 0;
    }

    sf_inited = true;
    if ((result=set_rand_seed()) != 0) {
        logCrit("file: "__FILE__", line: %d, "
                "set_rand_seed fail, program exit!", __LINE__);
        return result;
    }

    m = g_sf_global_vars.min_buff_size / (64 * 1024);
    if (m == 0) {
        m = 1;
    } else if (m > 16) {
        m = 16;
    }
    alloc_conn_once = ALLOC_CONNECTIONS_ONCE / m;
    init_connections = g_sf_global_vars.max_connections < alloc_conn_once ?
        g_sf_global_vars.max_connections : alloc_conn_once;
    if ((result=free_queue_init_ex2(g_sf_global_vars.max_connections,
                    init_connections, alloc_conn_once, g_sf_global_vars.
                    min_buff_size, g_sf_global_vars.max_buff_size,
                    task_arg_size, init_callback != NULL ?
                    init_callback : sf_init_task)) != 0)
    {
        return result;
    }

    return 0;
}

int sf_service_init_ex2(SFContext *sf_context, const char *name,
        sf_alloc_thread_extra_data_callback
        alloc_thread_extra_data_callback,
        ThreadLoopCallback thread_loop_callback,
        sf_accept_done_callback accept_done_callback,
        sf_set_body_length_callback set_body_length_func,
        sf_alloc_recv_buffer_callback alloc_recv_buffer_func,
        sf_send_done_callback send_done_callback,
        sf_deal_task_func deal_func, TaskCleanUpCallback task_cleanup_func,
        sf_recv_timeout_callback timeout_callback, const int net_timeout_ms,
        const int proto_header_size, const int task_arg_size,
        TaskInitCallback init_callback, sf_release_buffer_callback
        release_buffer_callback)
{
    int result;
    int bytes;
    int extra_events;
    struct worker_thread_context *thread_contexts;
    struct worker_thread_context *thread_ctx;
    struct nio_thread_data *thread_data;
    struct nio_thread_data *data_end;
    pthread_t tid;
    pthread_attr_t thread_attr;

    snprintf(sf_context->name, sizeof(sf_context->name), "%s", name);
    sf_context->realloc_task_buffer = g_sf_global_vars.
                    min_buff_size < g_sf_global_vars.max_buff_size;
    sf_context->accept_done_func = accept_done_callback;
    sf_set_parameters_ex(sf_context, proto_header_size,
            set_body_length_func, alloc_recv_buffer_func,
            send_done_callback, deal_func, task_cleanup_func,
            timeout_callback, release_buffer_callback);

    if ((result=sf_init_free_queues(task_arg_size, init_callback)) != 0) {
        return result;
    }

    if ((result=init_pthread_attr(&thread_attr, g_sf_global_vars.
                    thread_stack_size)) != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "init_pthread_attr fail, program exit!", __LINE__);
        return result;
    }

    bytes = sizeof(struct nio_thread_data) * sf_context->work_threads;
    sf_context->thread_data = (struct nio_thread_data *)fc_malloc(bytes);
    if (sf_context->thread_data == NULL) {
        return ENOMEM;
    }
    memset(sf_context->thread_data, 0, bytes);

    bytes = sizeof(struct worker_thread_context) * sf_context->work_threads;
    thread_contexts = (struct worker_thread_context *)fc_malloc(bytes);
    if (thread_contexts == NULL) {
        return ENOMEM;
    }

    if (SF_G_EPOLL_EDGE_TRIGGER) {
#ifdef OS_LINUX
        extra_events = EPOLLET;
#elif defined(OS_FREEBSD)
        extra_events = EV_CLEAR;
#else
        extra_events = 0;
#endif
    } else {
        extra_events = 0;
    }

    g_current_time = time(NULL);
    sf_context->thread_count = 0;
    data_end = sf_context->thread_data + sf_context->work_threads;
    for (thread_data=sf_context->thread_data,thread_ctx=thread_contexts;
            thread_data<data_end; thread_data++,thread_ctx++)
    {
        thread_data->thread_loop_callback = thread_loop_callback;
        if (alloc_thread_extra_data_callback != NULL) {
            thread_data->arg = alloc_thread_extra_data_callback(
                    (int)(thread_data - sf_context->thread_data));
        }
        else {
            thread_data->arg = NULL;
        }

        if (ioevent_init(&thread_data->ev_puller, 2 + g_sf_global_vars.
                    max_connections, net_timeout_ms, extra_events) != 0)
        {
            result  = errno != 0 ? errno : ENOMEM;
            logError("file: "__FILE__", line: %d, "
                "ioevent_init fail, "
                "errno: %d, error info: %s",
                __LINE__, result, strerror(result));
            return result;
        }

        result = fast_timer_init(&thread_data->timer,
                2 * g_sf_global_vars.network_timeout, g_current_time);
        if (result != 0) {
            logError("file: "__FILE__", line: %d, "
                    "fast_timer_init fail, errno: %d, error info: %s",
                    __LINE__, result, strerror(result));
            return result;
        }

        if ((result=init_pthread_lock(&thread_data->
                        waiting_queue.lock)) != 0)
        {
            return result;
        }
#if defined(OS_LINUX)
        FC_NOTIFY_READ_FD(thread_data) = eventfd(0,
                EFD_NONBLOCK | EFD_CLOEXEC);
        if (FC_NOTIFY_READ_FD(thread_data) < 0) {
            result = errno != 0 ? errno : EPERM;
            logError("file: "__FILE__", line: %d, "
                "call eventfd fail, "
                "errno: %d, error info: %s",
                __LINE__, result, strerror(result));
            break;
        }
        FC_NOTIFY_WRITE_FD(thread_data) = FC_NOTIFY_READ_FD(thread_data);
#else
        if (pipe(thread_data->pipe_fds) != 0) {
            result = errno != 0 ? errno : EPERM;
            logError("file: "__FILE__", line: %d, "
                "call pipe fail, "
                "errno: %d, error info: %s",
                __LINE__, result, strerror(result));
            break;
        }
        if ((result=fd_add_flags(FC_NOTIFY_READ_FD(thread_data),
                O_NONBLOCK)) != 0)
        {
            break;
        }
        FC_SET_CLOEXEC(FC_NOTIFY_READ_FD(thread_data));
        FC_SET_CLOEXEC(FC_NOTIFY_WRITE_FD(thread_data));
#endif

        thread_ctx->sf_context = sf_context;
        thread_ctx->thread_data = thread_data;
        if ((result=pthread_create(&tid, &thread_attr,
                        worker_thread_entrance, thread_ctx)) != 0)
        {
            logError("file: "__FILE__", line: %d, "
                    "create thread failed, startup threads: %d, "
                    "errno: %d, error info: %s",
                    __LINE__, (int)(thread_data - sf_context->thread_data),
                    result, strerror(result));
            break;
        }
    }
    pthread_attr_destroy(&thread_attr);

    return result;
}

int sf_service_destroy_ex(SFContext *sf_context)
{
    struct nio_thread_data *data_end, *thread_data;

    free_queue_destroy();
    data_end = sf_context->thread_data + sf_context->work_threads;
    for (thread_data=sf_context->thread_data; thread_data<data_end;
            thread_data++)
    {
        fast_timer_destroy(&thread_data->timer);
    }
    free(sf_context->thread_data);
    sf_context->thread_data = NULL;
    return 0;
}

void sf_service_set_thread_loop_callback_ex(SFContext *sf_context,
        ThreadLoopCallback thread_loop_callback)
{
    struct nio_thread_data *data_end, *thread_data;

    data_end = sf_context->thread_data + sf_context->work_threads;
    for (thread_data=sf_context->thread_data; thread_data<data_end;
            thread_data++)
    {
        thread_data->thread_loop_callback = thread_loop_callback;
    }
}

static void *worker_thread_entrance(void *arg)
{
    struct worker_thread_context *thread_ctx;
    int thread_count;

    thread_ctx = (struct worker_thread_context *)arg;

#ifdef OS_LINUX
    {
        char thread_name[32];
        snprintf(thread_name, sizeof(thread_name), "%s-net[%d]",
                thread_ctx->sf_context->name, (int)(thread_ctx->
                    thread_data - thread_ctx->sf_context->thread_data));
        prctl(PR_SET_NAME, thread_name);
    }
#endif

    thread_count = __sync_add_and_fetch(&thread_ctx->
            sf_context->thread_count, 1);

    logDebug("file: "__FILE__", line: %d, "
            "worker thread enter, current thread index: %d, "
            "current thread count: %d", __LINE__,
            (int)(thread_ctx->thread_data - thread_ctx->
                sf_context->thread_data), thread_count);

    ioevent_loop(thread_ctx->thread_data,
            sf_recv_notify_read,
            thread_ctx->sf_context->task_cleanup_func,
            &g_sf_global_vars.continue_flag);
    ioevent_destroy(&thread_ctx->thread_data->ev_puller);

    thread_count = __sync_sub_and_fetch(&thread_ctx->
            sf_context->thread_count, 1);

    logDebug("file: "__FILE__", line: %d, "
            "worker thread exit, current thread index: %d, "
            "current thread count: %d", __LINE__,
            (int)(thread_ctx->thread_data - thread_ctx->
                sf_context->thread_data), thread_count);
    return NULL;
}

int sf_create_socket_server(SFListener *listener, const char *bind_addr)
{
    int result;

    listener->sock = socketServer(bind_addr, listener->port, &result);
    if (listener->sock < 0) {
        return result;
    }

    if ((result=tcpsetserveropt(listener->sock, SF_G_NETWORK_TIMEOUT)) != 0) {
        return result;
    }

    return 0;
}

int sf_socket_server_ex(SFContext *sf_context)
{
    int result;
    bool dual_ports;
    const char *bind_addr;
    SFNetworkHandler *handler;
    SFNetworkHandler *end;

    end = sf_context->handlers + SF_NETWORK_HANDLER_COUNT;
    for (handler=sf_context->handlers; handler<end; handler++) {
        if (!handler->enabled) {
            continue;
        }

        handler->inner.enabled = false;
        handler->outer.enabled = false;
        if (handler->outer.port == handler->inner.port) {
            if (*sf_context->outer_bind_addr == '\0' ||
                    *sf_context->inner_bind_addr == '\0') {
                bind_addr = "";
                if ((result=handler->create_server(&handler->
                                outer, bind_addr)) != 0)
                {
                    return result;
                }
                handler->outer.enabled = true;
                dual_ports = false;
            } else if (strcmp(sf_context->outer_bind_addr,
                        sf_context->inner_bind_addr) == 0) {
                bind_addr = sf_context->outer_bind_addr;
                if (is_private_ip(bind_addr)) {
                    if ((result=handler->create_server(&handler->
                                    inner, bind_addr)) != 0)
                    {
                        return result;
                    }
                    handler->inner.enabled = true;
                } else {
                    if ((result=handler->create_server(&handler->
                                    outer, bind_addr)) != 0)
                    {
                        return result;
                    }
                    handler->outer.enabled = true;
                }
                dual_ports = false;
            } else {
                dual_ports = true;
            }
        } else {
            dual_ports = true;
        }

        if (dual_ports) {
            if ((result=handler->create_server(&handler->outer,
                            sf_context->outer_bind_addr)) != 0)
            {
                return result;
            }

            if ((result=handler->create_server(&handler->inner,
                            sf_context->inner_bind_addr)) != 0)
            {
                return result;
            }
            handler->inner.enabled = true;
            handler->outer.enabled = true;
        }

        /*
        logInfo("%p [%d] inner {port: %d, enabled: %d}, "
                "outer {port: %d, enabled: %d}", sf_context,
                (int)(handler-sf_context->handlers),
                handler->inner.port, handler->inner.enabled,
                handler->outer.port, handler->outer.enabled);
                */
    }

    return 0;
}

void sf_close_socket_server(SFListener *listener)
{
    if (listener->sock >= 0) {
        close(listener->sock);
        listener->sock = -1;
    }
}

struct fast_task_info *sf_accept_socket_connection(SFListener *listener)
{
    int incomesock;
    int port;
    socklen_t sockaddr_len;
    struct fast_task_info *task;

    sockaddr_len = sizeof(listener->inaddr);
    incomesock = accept(listener->sock, (struct sockaddr *)
            &listener->inaddr, &sockaddr_len);
    if (incomesock < 0) { //error
        if (!(errno == EINTR || errno == EAGAIN)) {
            logError("file: "__FILE__", line: %d, "
                    "accept fail, errno: %d, error info: %s",
                    __LINE__, errno, strerror(errno));
        }

        return NULL;
    }

    if (tcpsetnonblockopt(incomesock) != 0) {
        close(incomesock);
        return NULL;
    }
    FC_SET_CLOEXEC(incomesock);

    if ((task=sf_alloc_init_task(listener->handler, incomesock)) == NULL) {
        close(incomesock);
        return NULL;
    }

    getPeerIpAddPort(incomesock, task->client_ip,
            sizeof(task->client_ip), &port);
    task->port = port;
    return task;
}

void sf_close_socket_connection(struct fast_task_info *task)
{
    close(task->event.fd);
    task->event.fd = -1;
}

void sf_socket_close_ex(SFContext *sf_context)
{
    SFNetworkHandler *handler;
    SFNetworkHandler *end;

    end = sf_context->handlers + SF_NETWORK_HANDLER_COUNT;
    for (handler=sf_context->handlers; handler<end; handler++) {
        if (!handler->enabled) {
            continue;
        }
        if (handler->outer.enabled) {
            handler->close_server(&handler->outer);
        }
        if (handler->inner.enabled) {
            handler->close_server(&handler->inner);
        }
    }
}

static void accept_run(SFListener *listener)
{
    struct fast_task_info *task;

    while (g_sf_global_vars.continue_flag) {
        if ((task=listener->handler->accept_connection(listener)) == NULL) {
            continue;
        }

        task->thread_data = listener->handler->ctx->thread_data +
            task->event.fd % listener->handler->ctx->work_threads;
        if (listener->handler->ctx->accept_done_func != NULL) {
            if (listener->handler->ctx->accept_done_func(task,
                        listener->inaddr.sin_addr.s_addr,
                        listener->is_inner) != 0)
            {
                listener->handler->close_connection(task);
                sf_release_task(task);
                continue;
            }
        }

        if (sf_nio_notify(task, SF_NIO_STAGE_INIT) != 0) {
            listener->handler->close_connection(task);
            sf_release_task(task);
        }
    }
}

static void *accept_thread_entrance(SFListener *listener)
{
#ifdef OS_LINUX
    {
        char thread_name[32];
        snprintf(thread_name, sizeof(thread_name), "%s-%s-listen",
                listener->handler->type == fc_network_type_sock ?
                "sock" : "rdma", listener->handler->ctx->name);
        prctl(PR_SET_NAME, thread_name);
    }
#endif

    accept_run(listener);
    return NULL;
}

int _accept_loop(SFListener *listener, const int accept_threads)
{
    pthread_t tid;
    pthread_attr_t thread_attr;
    int result;
    int i;

    if (accept_threads <= 0) {
        return 0;
    }

    if ((result=init_pthread_attr(&thread_attr, g_sf_global_vars.
                    thread_stack_size)) != 0)
    {
        logWarning("file: "__FILE__", line: %d, "
                "init_pthread_attr fail!", __LINE__);
        return result;
    }

    for (i=0; i<accept_threads; i++) {
        if ((result=pthread_create(&tid, &thread_attr,
                        (void * (*)(void *))accept_thread_entrance,
                        listener)) != 0)
        {
            logError("file: "__FILE__", line: %d, "
                    "create thread failed, startup threads: %d, "
                    "errno: %d, error info: %s",
                    __LINE__, i, result, strerror(result));
            return result;
        }
    }

    pthread_attr_destroy(&thread_attr);
    return 0;
}

int sf_accept_loop_ex(SFContext *sf_context, const bool blocked)
{
    SFNetworkHandler *handler;
    SFNetworkHandler *hend;
    SFListener *listeners[SF_NETWORK_HANDLER_COUNT * 2];
    SFListener **listener;
    SFListener **last;
    SFListener **lend;

    listener = listeners;
    hend = sf_context->handlers + SF_NETWORK_HANDLER_COUNT;
    for (handler=sf_context->handlers; handler<hend; handler++) {
        if (!handler->enabled) {
            continue;
        }

        if (handler->inner.enabled) {
            *listener++ = &handler->inner;
        }
        if (handler->outer.enabled) {
            *listener++ = &handler->outer;
        }
    }

    if (listener == listeners) {
        logError("file: "__FILE__", line: %d, "
                "no listener!", __LINE__);
        return ENOENT;
    }

    last = listener - 1;
    if (blocked) {
        lend = listener - 1;
    } else {
        lend = listener;
    }

    for (listener=listeners; listener<lend; listener++) {
        _accept_loop(*listener, sf_context->accept_threads);
    }

    if (blocked) {
        _accept_loop(*last, sf_context->accept_threads - 1);
        accept_run(*last);
    }

    return 0;
}

#if defined(DEBUG_FLAG)
static void sigDumpHandler(int sig)
{
    static bool bDumpFlag = false;
    char filename[256];

    if (bDumpFlag) {
        return;
    }

    bDumpFlag = true;

    snprintf(filename, sizeof(filename), 
        "%s/logs/sf_dump.log", SF_G_BASE_PATH_STR);
    //manager_dump_global_vars_to_file(filename);

    bDumpFlag = false;
}
#endif

static void sigQuitHandler(int sig)
{
    if (!terminate_flag) {
        terminate_flag = true;
        g_sf_global_vars.continue_flag = false;
        if (sig_quit_handler != NULL) {
            sig_quit_handler(sig);
        }

        logCrit("file: "__FILE__", line: %d, "
                "catch signal %d, program exiting...",
                __LINE__, sig);
    }
}

static void sigHupHandler(int sig)
{
    logInfo("file: "__FILE__", line: %d, "
        "catch signal %d", __LINE__, sig);
}

static void sigUsrHandler(int sig)
{
    logInfo("file: "__FILE__", line: %d, "
        "catch signal %d, ignore it", __LINE__, sig);
}

int sf_setup_signal_handler()
{
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    sigemptyset(&act.sa_mask);

    act.sa_handler = sigUsrHandler;
    if(sigaction(SIGUSR1, &act, NULL) < 0 ||
        sigaction(SIGUSR2, &act, NULL) < 0)
    {
        logCrit("file: "__FILE__", line: %d, "
            "call sigaction fail, errno: %d, error info: %s",
            __LINE__, errno, strerror(errno));
        logCrit("exit abnormally!\n");
        return errno;
    }

    act.sa_handler = sigHupHandler;
    if(sigaction(SIGHUP, &act, NULL) < 0) {
        logCrit("file: "__FILE__", line: %d, "
            "call sigaction fail, errno: %d, error info: %s",
            __LINE__, errno, strerror(errno));
        logCrit("exit abnormally!\n");
        return errno;
    }
    
    act.sa_handler = SIG_IGN;
    if(sigaction(SIGPIPE, &act, NULL) < 0) {
        logCrit("file: "__FILE__", line: %d, "
            "call sigaction fail, errno: %d, error info: %s",
            __LINE__, errno, strerror(errno));
        logCrit("exit abnormally!\n");
        return errno;
    }

    act.sa_handler = sigQuitHandler;
    if(sigaction(SIGINT, &act, NULL) < 0 ||
        sigaction(SIGTERM, &act, NULL) < 0 ||
        sigaction(SIGQUIT, &act, NULL) < 0)
    {
        logCrit("file: "__FILE__", line: %d, "
            "call sigaction fail, errno: %d, error info: %s",
            __LINE__, errno, strerror(errno));
        logCrit("exit abnormally!\n");
        return errno;
    }

#if defined(DEBUG_FLAG)
    memset(&act, 0, sizeof(act));
    sigemptyset(&act.sa_mask);
    act.sa_handler = sigDumpHandler;
    if(sigaction(SIGUSR1, &act, NULL) < 0 ||
        sigaction(SIGUSR2, &act, NULL) < 0)
    {
        logCrit("file: "__FILE__", line: %d, "
            "call sigaction fail, errno: %d, error info: %s",
            __LINE__, errno, strerror(errno));
        logCrit("exit abnormally!\n");
        return errno;
    }
#endif
    return 0;
}

#define LOG_SCHEDULE_ENTRIES_COUNT 3

int sf_startup_schedule(pthread_t *schedule_tid)
{
    ScheduleArray scheduleArray;
    ScheduleEntry scheduleEntries[LOG_SCHEDULE_ENTRIES_COUNT];

    scheduleArray.entries = scheduleEntries;
    sf_setup_schedule(&g_log_context, &g_sf_global_vars.error_log,
            &scheduleArray);
    return sched_start(&scheduleArray, schedule_tid,
            g_sf_global_vars.thread_stack_size, (bool * volatile)
            &g_sf_global_vars.continue_flag);
}

int sf_add_slow_log_schedule(SFSlowLogContext *slowlog_ctx)
{
    int result;
    ScheduleArray scheduleArray;
    ScheduleEntry scheduleEntries[LOG_SCHEDULE_ENTRIES_COUNT];

    if (!slowlog_ctx->cfg.enabled) {
        return 0;
    }

    if ((result=sf_logger_init(&slowlog_ctx->ctx, slowlog_ctx->cfg.
                    filename_prefix)) != 0)
    {
        return result;
    }

    scheduleArray.entries = scheduleEntries;
    sf_setup_schedule(&slowlog_ctx->ctx, &slowlog_ctx->cfg.log_cfg,
            &scheduleArray);
    return sched_add_entries(&scheduleArray);
}

void sf_set_current_time()
{
    g_current_time = time(NULL);
    g_sf_global_vars.up_time = g_current_time;
    srand(g_sf_global_vars.up_time);
}

void sf_enable_thread_notify_ex(SFContext *sf_context, const bool enabled)
{
    struct nio_thread_data *thread_data;
    struct nio_thread_data *pDataEnd;

    pDataEnd = sf_context->thread_data + sf_context->work_threads;
    for (thread_data=sf_context->thread_data; thread_data<pDataEnd;
            thread_data++)
    {
        thread_data->notify.enabled = enabled;
    }
}

struct nio_thread_data *sf_get_random_thread_data_ex(SFContext *sf_context)
{
    uint32_t index;
    index = (uint32_t)((uint64_t)sf_context->work_threads *
            (uint64_t)rand() / (uint64_t)RAND_MAX);
    return sf_context->thread_data + index;
}

void sf_notify_all_threads_ex(SFContext *sf_context)
{
    struct nio_thread_data *tdata;
    struct nio_thread_data *tend;

    tend = sf_context->thread_data + sf_context->work_threads;
    for (tdata=sf_context->thread_data; tdata<tend; tdata++) {
        ioevent_notify_thread(tdata);
    }
}

void sf_set_sig_quit_handler(sf_sig_quit_handler quit_handler)
{
    sig_quit_handler = quit_handler;
}
