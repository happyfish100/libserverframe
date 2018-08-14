#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/sched_thread.h"
#include "fastcommon/pthread_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/sockopt.h"
#include "fastcommon/fast_task_queue.h"
#include "fastcommon/ioevent_loop.h"
#include "sf_global.h"
#include "sf_types.h"
#include "sf_nio.h"

static int sf_header_size = 0;
static bool sf_remove_from_ready_list = true;
static sf_deal_task_func sf_deal_task = NULL;
static sf_set_body_length_callback sf_set_body_length = NULL;
static TaskCleanUpCallback sf_task_cleanup_func = sf_task_finish_clean_up;
static sf_recv_timeout_callback sf_timeout_callback = NULL;

void sf_set_parameters(const int header_size, sf_set_body_length_callback
        set_body_length_func, sf_deal_task_func deal_func,
        TaskCleanUpCallback cleanup_func,
        sf_recv_timeout_callback timeout_callback)
{
    sf_header_size = header_size;
    sf_set_body_length = set_body_length_func;
    sf_deal_task = deal_func;
    sf_task_cleanup_func = cleanup_func;
    sf_timeout_callback = timeout_callback;
}

void sf_set_remove_from_ready_list(const bool enabled)
{
    sf_remove_from_ready_list = enabled;
}

TaskCleanUpCallback sf_get_task_cleanup_func()
{
    return sf_task_cleanup_func; 
}

void sf_task_finish_clean_up(struct fast_task_info *pTask)
{
    assert(pTask->event.fd >= 0);
    /*
    if (pTask->event.fd < 0) {
        logWarning("file: "__FILE__", line: %d, "
                "pTask: %p already cleaned",
                __LINE__, pTask);
        return;
    }
    */

    if (pTask->finish_callback != NULL) {
        pTask->finish_callback(pTask);
        pTask->finish_callback = NULL;
    }

    ioevent_detach(&pTask->thread_data->ev_puller, pTask->event.fd);
    close(pTask->event.fd);
    pTask->event.fd = -1;

    if (pTask->event.timer.expires > 0) {
        fast_timer_remove(&pTask->thread_data->timer,
            &pTask->event.timer);
        pTask->event.timer.expires = 0;
    }

    if (sf_remove_from_ready_list) {
        ioevent_remove(&pTask->thread_data->ev_puller, pTask);
    }

    __sync_fetch_and_sub(&g_sf_global_vars.connection_stat.current_count, 1);
    free_queue_push(pTask);
}

void sf_recv_notify_read(int sock, short event, void *arg)
{
    int bytes;
    int current_connections;
    long task_ptr;
    struct fast_task_info *pTask;

    while (1) {
        if ((bytes=read(sock, &task_ptr, sizeof(task_ptr))) < 0) {
            if (!(errno == EAGAIN || errno == EWOULDBLOCK)) {
                logError("file: "__FILE__", line: %d, "
                    "call read failed, "
                    "errno: %d, error info: %s",
                    __LINE__, errno, strerror(errno));
            }

            break;
        }
        else if (bytes == 0) {
            break;
        }

        current_connections = __sync_add_and_fetch(
                &g_sf_global_vars.connection_stat.current_count, 1);
        if (current_connections > g_sf_global_vars.connection_stat.max_count) {
            g_sf_global_vars.connection_stat.max_count = current_connections;
        }

        pTask = (struct fast_task_info *)task_ptr;
        if (ioevent_set(pTask, pTask->thread_data, pTask->event.fd,
                    IOEVENT_READ, (IOEventCallback)sf_client_sock_read,
                    g_sf_global_vars.network_timeout) != 0)
        {
            sf_task_cleanup_func(pTask);
            continue;
        }
    }
}

static inline int set_write_event(struct fast_task_info *pTask)
{
    int result;

    if (pTask->event.callback == (IOEventCallback)sf_client_sock_write) {
        return 0;
    }

    pTask->event.callback = (IOEventCallback)sf_client_sock_write;
    if (ioevent_modify(&pTask->thread_data->ev_puller,
        pTask->event.fd, IOEVENT_WRITE, pTask) != 0)
    {
        result = errno != 0 ? errno : ENOENT;
        sf_task_cleanup_func(pTask);

        logError("file: "__FILE__", line: %d, "
            "ioevent_modify fail, "
            "errno: %d, error info: %s",
            __LINE__, result, strerror(result));
        return result;
    }
    return 0;
}

static inline int set_read_event(struct fast_task_info *pTask)
{
    int result;

    if (pTask->event.callback == (IOEventCallback)sf_client_sock_read) {
        return 0;
    }

    pTask->event.callback = (IOEventCallback)sf_client_sock_read;
    if (ioevent_modify(&pTask->thread_data->ev_puller,
                pTask->event.fd, IOEVENT_READ, pTask) != 0)
    {
        result = errno != 0 ? errno : ENOENT;
        sf_task_cleanup_func(pTask);

        logError("file: "__FILE__", line: %d, "
                "ioevent_modify fail, "
                "errno: %d, error info: %s",
                __LINE__, result, strerror(result));
        return result;
    }

    return 0;
}

int sf_send_add_event(struct fast_task_info *pTask)
{
    pTask->offset = 0;
    if (pTask->length > 0) {
        /* direct send */
        if (sf_client_sock_write(pTask->event.fd, IOEVENT_WRITE, pTask) < 0) {
            return errno != 0 ? errno : EIO;
        }
    }

    return 0;
}

int sf_client_sock_read(int sock, short event, void *arg)
{
    int bytes;
    int recv_bytes;
    int total_read;
    struct fast_task_info *pTask;

    assert(sock >= 0);
    pTask = (struct fast_task_info *)arg;
    if (event & IOEVENT_TIMEOUT) {
        if (pTask->offset == 0 && pTask->req_count > 0) {
            if (sf_timeout_callback != NULL) {
                if (sf_timeout_callback(pTask) != 0) {
                    sf_task_cleanup_func(pTask);
                    return -1;
                }
            }

            pTask->event.timer.expires = g_current_time +
                g_sf_global_vars.network_timeout;
            fast_timer_add(&pTask->thread_data->timer,
                &pTask->event.timer);
        }
        else {
            if (pTask->length > 0) {
                logWarning("file: "__FILE__", line: %d, "
                        "client ip: %s, recv timeout, "
                        "recv offset: %d, expect length: %d",
                        __LINE__, pTask->client_ip,
                        pTask->offset, pTask->length);
            }
            else {
                logWarning("file: "__FILE__", line: %d, "
                        "client ip: %s, req_count: %"PRId64", recv timeout",
                        __LINE__, pTask->client_ip,  pTask->req_count);
            }

            sf_task_cleanup_func(pTask);
            return -1;
        }

        return 0;
    }

    if (event & IOEVENT_ERROR) {
        logDebug("file: "__FILE__", line: %d, "
            "client ip: %s, recv error event: %d, "
            "close connection", __LINE__, pTask->client_ip, event);

        sf_task_cleanup_func(pTask);
        return -1;
    }

    total_read = 0;
    while (1) {
        fast_timer_modify(&pTask->thread_data->timer,
            &pTask->event.timer, g_current_time +
            g_sf_global_vars.network_timeout);
        if (pTask->length == 0) { //recv header
            recv_bytes = sf_header_size - pTask->offset;
        }
        else {
            recv_bytes = pTask->length - pTask->offset;
        }

        bytes = read(sock, pTask->data + pTask->offset, recv_bytes);
        if (bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            else if (errno == EINTR) {  //should retry
                logDebug("file: "__FILE__", line: %d, "
                    "client ip: %s, ignore interupt signal",
                    __LINE__, pTask->client_ip);
                continue;
            }
            else {
                logWarning("file: "__FILE__", line: %d, "
                    "client ip: %s, recv failed, "
                    "errno: %d, error info: %s",
                    __LINE__, pTask->client_ip,
                    errno, strerror(errno));

                sf_task_cleanup_func(pTask);
                return -1;
            }
        }
        else if (bytes == 0) {
            logDebug("file: "__FILE__", line: %d, "
                "client ip: %s, sock: %d, recv failed, "
                "connection disconnected",
                __LINE__, pTask->client_ip, sock);

            sf_task_cleanup_func(pTask);
            return -1;
        }

        total_read += bytes;
        pTask->offset += bytes;
        if (pTask->length == 0) { //header
            if (pTask->offset < sf_header_size) {
                break;
            }

            if (sf_set_body_length(pTask) != 0) {
                sf_task_cleanup_func(pTask);
                return -1;
            }
            if (pTask->length < 0) {
                logError("file: "__FILE__", line: %d, "
                    "client ip: %s, pkg length: %d < 0",
                    __LINE__, pTask->client_ip,
                    pTask->length);

                sf_task_cleanup_func(pTask);
                return -1;
            }

            pTask->length += sf_header_size;
            if (pTask->length > g_sf_global_vars.max_pkg_size) {
                logError("file: "__FILE__", line: %d, "
                    "client ip: %s, pkg length: %d > "
                    "max pkg size: %d", __LINE__,
                    pTask->client_ip, pTask->length,
                    g_sf_global_vars.max_pkg_size);

                sf_task_cleanup_func(pTask);
                return -1;
            }

            if (pTask->length > pTask->size) {
                int old_size;
                old_size = pTask->size;
                if (free_queue_realloc_buffer(pTask, pTask->length) != 0) {
                    logError("file: "__FILE__", line: %d, "
                            "client ip: %s, realloc buffer size "
                            "from %d to %d fail", __LINE__,
                            pTask->client_ip, pTask->size, pTask->length);

                    sf_task_cleanup_func(pTask);
                    return -1;
                }

                logDebug("file: "__FILE__", line: %d, "
                        "client ip: %s, task length: %d, realloc buffer size "
                        "from %d to %d", __LINE__, pTask->client_ip,
                        pTask->length, old_size, pTask->size);
            }
        }

        if (pTask->offset >= pTask->length) { //recv done
            pTask->req_count++;
            if (sf_deal_task(pTask) < 0) {  //fatal error
                sf_task_cleanup_func(pTask);
                return -1;
            }
            break;
        }
    }

    return total_read;
}

int sf_client_sock_write(int sock, short event, void *arg)
{
    int bytes;
    int total_write;
    struct fast_task_info *pTask;

    assert(sock >= 0);
    pTask = (struct fast_task_info *)arg;
    if (event & IOEVENT_TIMEOUT) {
        logError("file: "__FILE__", line: %d, "
            "client ip: %s, send timeout. total length: %d, offset: %d, "
            "remain: %d", __LINE__, pTask->client_ip, pTask->length,
            pTask->offset, pTask->length - pTask->offset);

        sf_task_cleanup_func(pTask);
        return -1;
    }

    if (event & IOEVENT_ERROR) {
        logDebug("file: "__FILE__", line: %d, "
            "client ip: %s, recv error event: %d, "
            "close connection", __LINE__, pTask->client_ip, event);

        sf_task_cleanup_func(pTask);
        return -1;
    }

    total_write = 0;
    while (1) {
        fast_timer_modify(&pTask->thread_data->timer,
            &pTask->event.timer, g_current_time +
            g_sf_global_vars.network_timeout);

        bytes = write(sock, pTask->data + pTask->offset,
                pTask->length - pTask->offset);
        if (bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                if (set_write_event(pTask) != 0) {
                    return -1;
                }
                break;
            }
            else if (errno == EINTR) {  //should retry
                logDebug("file: "__FILE__", line: %d, "
                    "client ip: %s, ignore interupt signal",
                    __LINE__, pTask->client_ip);
                continue;
            }
            else {
                logWarning("file: "__FILE__", line: %d, "
                    "client ip: %s, send fail, "
                    "errno: %d, error info: %s",
                    __LINE__, pTask->client_ip,
                    errno, strerror(errno));

                sf_task_cleanup_func(pTask);
                return -1;
            }
        }
        else if (bytes == 0) {
            logWarning("file: "__FILE__", line: %d, "
                "client ip: %s, sock: %d, send failed, connection disconnected",
                __LINE__, pTask->client_ip, sock);

            sf_task_cleanup_func(pTask);
            return -1;
        }

        total_write += bytes;
        pTask->offset += bytes;
        if (pTask->offset >= pTask->length) {
            pTask->offset = 0;
            pTask->length = 0;
            if (set_read_event(pTask) != 0) {
                return -1;
            }
            break;
        }
    }

    return total_write;
}

