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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
//#include <assert.h>
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
#include "sf_service.h"
#include "sf_nio.h"

#define SF_CTX  ((SFContext *)(task->ctx))

void sf_set_parameters_ex(SFContext *sf_context, const int header_size,
        sf_set_body_length_callback set_body_length_func,
        sf_deal_task_func deal_func, TaskCleanUpCallback cleanup_func,
        sf_recv_timeout_callback timeout_callback, sf_release_buffer_callback
        release_buffer_callback)
{
    sf_context->header_size = header_size;
    sf_context->set_body_length = set_body_length_func;
    sf_context->deal_task = deal_func;
    sf_context->task_cleanup_func = cleanup_func;
    sf_context->timeout_callback = timeout_callback;
    sf_context->release_buffer_callback = release_buffer_callback;
}

void sf_task_detach_thread(struct fast_task_info *task)
{
    ioevent_detach(&task->thread_data->ev_puller, task->event.fd);

    if (task->event.timer.expires > 0) {
        fast_timer_remove(&task->thread_data->timer,
                &task->event.timer);
        task->event.timer.expires = 0;
    }

    if (SF_CTX->remove_from_ready_list) {
        ioevent_remove(&task->thread_data->ev_puller, task);
    }
}

void sf_task_switch_thread(struct fast_task_info *task,
        const int new_thread_index)
{
    sf_task_detach_thread(task);
    task->thread_data = SF_CTX->thread_data + new_thread_index;
}

static inline void release_iovec_buffer(struct fast_task_info *task)
{
    if (task->iovec_array.iovs != NULL) {
        if (SF_CTX->release_buffer_callback != NULL) {
            SF_CTX->release_buffer_callback(task);
        }
        task->iovec_array.iovs = NULL;
        task->iovec_array.count = 0;
    }
}

void sf_task_finish_clean_up(struct fast_task_info *task)
{
    /*
    assert(task->event.fd >= 0);
    if (task->event.fd < 0) {
        logWarning("file: "__FILE__", line: %d, "
                "task: %p already cleaned",
                __LINE__, task);
        return;
    }
    */

    if (task->finish_callback != NULL) {
        task->finish_callback(task);
        task->finish_callback = NULL;
    }

    release_iovec_buffer(task);

    sf_task_detach_thread(task);
    close(task->event.fd);
    task->event.fd = -1;

    __sync_fetch_and_sub(&g_sf_global_vars.connection_stat.current_count, 1);
    sf_release_task(task);
}

static inline int set_write_event(struct fast_task_info *task)
{
    int result;

    if (task->event.callback == (IOEventCallback)sf_client_sock_write) {
        return 0;
    }

    task->event.callback = (IOEventCallback)sf_client_sock_write;
    if (ioevent_modify(&task->thread_data->ev_puller,
        task->event.fd, IOEVENT_WRITE, task) != 0)
    {
        result = errno != 0 ? errno : ENOENT;
        ioevent_add_to_deleted_list(task);

        logError("file: "__FILE__", line: %d, "
            "ioevent_modify fail, "
            "errno: %d, error info: %s",
            __LINE__, result, strerror(result));
        return result;
    }
    return 0;
}

int sf_set_read_event(struct fast_task_info *task)
{
    int result;

    task->nio_stages.current = SF_NIO_STAGE_RECV;
    if (task->event.callback == (IOEventCallback)sf_client_sock_read) {
        return 0;
    }

    task->event.callback = (IOEventCallback)sf_client_sock_read;
    if (ioevent_modify(&task->thread_data->ev_puller,
                task->event.fd, IOEVENT_READ, task) != 0)
    {
        result = errno != 0 ? errno : ENOENT;
        ioevent_add_to_deleted_list(task);

        logError("file: "__FILE__", line: %d, "
                "ioevent_modify fail, "
                "errno: %d, error info: %s",
                __LINE__, result, strerror(result));
        return result;
    }

    return 0;
}

static inline int sf_ioevent_add(struct fast_task_info *task,
        IOEventCallback callback, const int timeout)
{
    int result;

    result = ioevent_set(task, task->thread_data, task->event.fd,
            IOEVENT_READ, callback, timeout);
    return result > 0 ? -1 * result : result;
}

static inline int sf_nio_init(struct fast_task_info *task)
{
    int current_connections;

    current_connections = __sync_add_and_fetch(
            &g_sf_global_vars.connection_stat.current_count, 1);
    if (current_connections > g_sf_global_vars.connection_stat.max_count) {
        g_sf_global_vars.connection_stat.max_count = current_connections;
    }

    return sf_ioevent_add(task, (IOEventCallback)sf_client_sock_read,
            task->network_timeout);
}

static int sf_client_sock_connect(int sock, short event, void *arg)
{
    int result;
    socklen_t len;
    struct fast_task_info *task;

    task = (struct fast_task_info *)arg;
    if (event & IOEVENT_TIMEOUT) {
        result = ETIMEDOUT;
    } else {
        len = sizeof(result);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &result, &len) < 0) {
            result = errno != 0 ? errno : EACCES;
        }
    }

    if (result != 0) {
        logError("file: "__FILE__", line: %d, "
                "connect to server %s:%u fail, errno: %d, "
                "error info: %s", __LINE__, task->server_ip,
                task->port, result, STRERROR(result));
        ioevent_add_to_deleted_list(task);
        return -1;
    }

    logInfo("file: "__FILE__", line: %d, "
            "connect to server %s:%u successfully",
            __LINE__, task->server_ip, task->port);
    return SF_CTX->deal_task(task, SF_NIO_STAGE_HANDSHAKE);
}

static int sf_connect_server(struct fast_task_info *task)
{
    int result;

    if ((task->event.fd=socketCreateEx2(AF_UNSPEC, task->server_ip,
                    O_NONBLOCK, NULL, &result)) < 0)
    {
        return result > 0 ? -1 * result : result;
    }

    result = asyncconnectserverbyip(task->event.fd,
            task->server_ip, task->port);
    if (result == 0) {
        if ((result=sf_ioevent_add(task, (IOEventCallback)
                sf_client_sock_read, task->network_timeout)) != 0)
        {
            return result;
        }

        logInfo("file: "__FILE__", line: %d, "
                "connect to server %s:%u successfully",
                __LINE__, task->server_ip, task->port);
        return SF_CTX->deal_task(task, SF_NIO_STAGE_HANDSHAKE);
    } else if (result == EINPROGRESS) {
        result = ioevent_set(task, task->thread_data, task->event.fd,
                IOEVENT_READ | IOEVENT_WRITE, (IOEventCallback)
                sf_client_sock_connect, task->connect_timeout);
        return result > 0 ? -1 * result : result;
    } else {
        close(task->event.fd);
        task->event.fd = -1;
        logError("file: "__FILE__", line: %d, "
                "connect to server %s:%u fail, errno: %d, "
                "error info: %s", __LINE__, task->server_ip,
                task->port, result, STRERROR(result));
        return result > 0 ? -1 * result : result;
    }
}

static int sf_nio_deal_task(struct fast_task_info *task, const int stage)
{
    int result;

    switch (stage) {
        case SF_NIO_STAGE_INIT:
            task->nio_stages.current = SF_NIO_STAGE_RECV;
            result = sf_nio_init(task);
            break;
        case SF_NIO_STAGE_CONNECT:
            result = sf_connect_server(task);
            break;
        case SF_NIO_STAGE_RECV:
            if ((result=sf_set_read_event(task)) == 0)
            {
                sf_client_sock_read(task->event.fd,
                        IOEVENT_READ, task);
            }
            break;
        case SF_NIO_STAGE_SEND:
            result = sf_send_add_event(task);
            break;
        case SF_NIO_STAGE_CONTINUE:   //continue deal
            result = SF_CTX->deal_task(task, SF_NIO_STAGE_CONTINUE);
            break;
        case SF_NIO_STAGE_FORWARDED:  //forward by other thread
            if ((result=sf_ioevent_add(task, (IOEventCallback)
                            sf_client_sock_read,
                            task->network_timeout)) == 0)
            {
                result = SF_CTX->deal_task(task, SF_NIO_STAGE_SEND);
            }
            break;
        case SF_NIO_STAGE_CLOSE:
            result = -EIO;   //close this socket
            break;
        default:
            logError("file: "__FILE__", line: %d, "
                    "client ip: %s, invalid notify stage: %d",
                    __LINE__, task->client_ip, stage);
            result = -EINVAL;
            break;
    }

    if (result < 0) {
        ioevent_add_to_deleted_list(task);
    }

    return result;
}

int sf_nio_notify(struct fast_task_info *task, const int stage)
{
    int64_t n;
    int result;
    int old_stage;
    bool notify;

    if (__sync_add_and_fetch(&task->canceled, 0)) {
        if (stage == SF_NIO_STAGE_CONTINUE) {
            if (task->continue_callback != NULL) {
                return task->continue_callback(task);
            } else {
                logWarning("file: "__FILE__", line: %d, "
                        "task %p, continue_callback is NULL",
                        __LINE__, task);
                return 0;
            }
        } else {
            logWarning("file: "__FILE__", line: %d, "
                    "unexpected notify stage: %d, task %p "
                    "already canceled", __LINE__, stage, task);
            return ECANCELED;
        }
    }

    while (!__sync_bool_compare_and_swap(&task->nio_stages.notify,
                SF_NIO_STAGE_NONE, stage))
    {
        old_stage = __sync_fetch_and_add(&task->nio_stages.notify, 0);
        if (old_stage == stage) {
            logDebug("file: "__FILE__", line: %d, "
                    "current stage: %d equals to the target, skip set",
                    __LINE__, stage);
            return 0;
        } else if (old_stage != SF_NIO_STAGE_NONE) {
            logWarning("file: "__FILE__", line: %d, "
                    "current stage: %d != %d, skip set stage to %d",
                    __LINE__, old_stage, SF_NIO_STAGE_NONE, stage);
            return EAGAIN;
        }
    }

    PTHREAD_MUTEX_LOCK(&task->thread_data->waiting_queue.lock);
    task->next = NULL;

    if (task->thread_data->waiting_queue.tail == NULL) {
        task->thread_data->waiting_queue.head = task;
        notify = true;
    } else {
        task->thread_data->waiting_queue.tail->next = task;
        notify = false;
    }
    task->thread_data->waiting_queue.tail = task;
    PTHREAD_MUTEX_UNLOCK(&task->thread_data->waiting_queue.lock);

    if (notify) {
        n = 1;
        if (write(FC_NOTIFY_WRITE_FD(task->thread_data),
                    &n, sizeof(n)) != sizeof(n))
        {
            result = errno != 0 ? errno : EIO;
            logError("file: "__FILE__", line: %d, "
                    "write eventfd %d fail, errno: %d, error info: %s",
                    __LINE__, FC_NOTIFY_WRITE_FD(task->thread_data),
                    result, STRERROR(result));
            return result;
        }
    }

    return 0;
}

void sf_recv_notify_read(int sock, short event, void *arg)
{
    int64_t n;
    int stage;
    struct nio_thread_data *thread_data;
    struct fast_task_info *task;
    struct fast_task_info *current;

    thread_data = ((struct ioevent_notify_entry *)arg)->thread_data;
    if (read(sock, &n, sizeof(n)) < 0) {
        logWarning("file: "__FILE__", line: %d, "
                "read from eventfd %d fail, errno: %d, error info: %s",
                __LINE__, sock, errno, STRERROR(errno));
    }

    PTHREAD_MUTEX_LOCK(&thread_data->waiting_queue.lock);
    current = thread_data->waiting_queue.head;
    thread_data->waiting_queue.head = thread_data->waiting_queue.tail = NULL;
    PTHREAD_MUTEX_UNLOCK(&thread_data->waiting_queue.lock);

    while (current != NULL) {
        task = current;
        current = current->next;

        stage = __sync_add_and_fetch(&task->nio_stages.notify, 0);
        if (!task->canceled) {
            if (stage == SF_NIO_STAGE_CONTINUE) {
                /* MUST set to SF_NIO_STAGE_NONE first for re-entry */
                __sync_bool_compare_and_swap(&task->nio_stages.notify,
                        stage, SF_NIO_STAGE_NONE);
                sf_nio_deal_task(task, stage);
            } else {
                sf_nio_deal_task(task, stage);
                __sync_bool_compare_and_swap(&task->nio_stages.notify,
                        stage, SF_NIO_STAGE_NONE);
            }
        } else {
            if (stage != SF_NIO_STAGE_NONE) {
                if (stage == SF_NIO_STAGE_CONTINUE) {
                    if (task->continue_callback != NULL) {
                        task->continue_callback(task);
                    } else {
                        logWarning("file: "__FILE__", line: %d, "
                                "task %p, continue_callback is NULL",
                                __LINE__, task);
                    }
                }
                __sync_bool_compare_and_swap(&task->nio_stages.notify,
                        stage, SF_NIO_STAGE_NONE);
            }
        }
    }
}

int sf_send_add_event(struct fast_task_info *task)
{
    task->offset = 0;
    if (task->length > 0) {
        /* direct send */
        task->nio_stages.current = SF_NIO_STAGE_SEND;
        if (sf_client_sock_write(task->event.fd, IOEVENT_WRITE, task) < 0) {
            return errno != 0 ? errno : EIO;
        }
    }

    return 0;
}

static inline int check_task(struct fast_task_info *task,
        const short event, const int expect_stage)
{
    if (task->canceled) {
        return ENOTCONN;
    }

    if (event & IOEVENT_ERROR) {
        logDebug("file: "__FILE__", line: %d, "
                "client ip: %s, expect stage: %d, recv error event: %d, "
                "close connection", __LINE__, task->client_ip,
                expect_stage, event);

        ioevent_add_to_deleted_list(task);
        return -1;
    }

    return task->nio_stages.current == expect_stage ? 0 : EAGAIN;
}

int sf_client_sock_read(int sock, short event, void *arg)
{
    int result;
    int bytes;
    int recv_bytes;
    int total_read;
    struct fast_task_info *task;

    task = (struct fast_task_info *)arg;
    if ((result=check_task(task, event, SF_NIO_STAGE_RECV)) != 0) {
        return result >= 0 ? 0 : -1;
    }

    if (event & IOEVENT_TIMEOUT) {
        if (task->offset == 0 && task->req_count > 0) {
            if (SF_CTX->timeout_callback != NULL) {
                if (SF_CTX->timeout_callback(task) != 0) {
                    ioevent_add_to_deleted_list(task);
                    return -1;
                }
            }

            task->event.timer.expires = g_current_time +
                task->network_timeout;
            fast_timer_add(&task->thread_data->timer,
                &task->event.timer);
        } else {
            if (task->length > 0) {
                logWarning("file: "__FILE__", line: %d, "
                        "client ip: %s, recv timeout, "
                        "recv offset: %d, expect length: %d",
                        __LINE__, task->client_ip,
                        task->offset, task->length);
            } else {
                logWarning("file: "__FILE__", line: %d, "
                        "client ip: %s, req_count: %"PRId64", recv timeout",
                        __LINE__, task->client_ip,  task->req_count);
            }

            ioevent_add_to_deleted_list(task);
            return -1;
        }

        return 0;
    }

    total_read = 0;
    while (1) {
        fast_timer_modify(&task->thread_data->timer,
            &task->event.timer, g_current_time +
            task->network_timeout);
        if (task->length == 0) { //recv header
            recv_bytes = SF_CTX->header_size - task->offset;
        } else {
            recv_bytes = task->length - task->offset;
        }

        bytes = read(sock, task->data + task->offset, recv_bytes);
        if (bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else if (errno == EINTR) {  //should retry
                logDebug("file: "__FILE__", line: %d, "
                    "client ip: %s, ignore interupt signal",
                    __LINE__, task->client_ip);
                continue;
            } else {
                logWarning("file: "__FILE__", line: %d, "
                    "client ip: %s, recv fail, "
                    "errno: %d, error info: %s",
                    __LINE__, task->client_ip,
                    errno, strerror(errno));

                ioevent_add_to_deleted_list(task);
                return -1;
            }
        } else if (bytes == 0) {
            if (task->offset > 0) {
                if (task->length > 0) {
                    logWarning("file: "__FILE__", line: %d, "
                            "client ip: %s, connection "
                            "disconnected, expect pkg length: %d, "
                            "recv pkg length: %d", __LINE__,
                            task->client_ip, task->length,
                            task->offset);
                } else {
                    logWarning("file: "__FILE__", line: %d, "
                            "client ip: %s, connection "
                            "disconnected, recv pkg length: %d",
                            __LINE__, task->client_ip,
                            task->offset);
                }
            } else {
                logDebug("file: "__FILE__", line: %d, "
                        "client ip: %s, sock: %d, recv fail, "
                        "connection disconnected",
                        __LINE__, task->client_ip, sock);
            }

            ioevent_add_to_deleted_list(task);
            return -1;
        }

        TCP_SET_QUICK_ACK(sock);
        total_read += bytes;
        task->offset += bytes;
        if (task->length == 0) { //header
            if (task->offset < SF_CTX->header_size) {
                break;
            }

            if (SF_CTX->set_body_length(task) != 0) {
                ioevent_add_to_deleted_list(task);
                return -1;
            }
            if (task->length < 0) {
                logError("file: "__FILE__", line: %d, "
                    "client ip: %s, pkg length: %d < 0",
                    __LINE__, task->client_ip,
                    task->length);

                ioevent_add_to_deleted_list(task);
                return -1;
            }

            task->length += SF_CTX->header_size;
            if (task->length > g_sf_global_vars.max_pkg_size) {
                logError("file: "__FILE__", line: %d, "
                    "client ip: %s, pkg length: %d > "
                    "max pkg size: %d", __LINE__,
                    task->client_ip, task->length,
                    g_sf_global_vars.max_pkg_size);

                ioevent_add_to_deleted_list(task);
                return -1;
            }

            if (task->length > task->size) {
                int old_size;

                if (!SF_CTX->realloc_task_buffer) {
                    logError("file: "__FILE__", line: %d, "
                            "client ip: %s, pkg length: %d exceeds "
                            "task size: %d, but realloc buffer disabled",
                            __LINE__, task->client_ip, task->size,
                            task->length);

                    ioevent_add_to_deleted_list(task);
                    return -1;
                }

                old_size = task->size;
                if (free_queue_realloc_buffer(task, task->length) != 0) {
                    logError("file: "__FILE__", line: %d, "
                            "client ip: %s, realloc buffer size "
                            "from %d to %d fail", __LINE__,
                            task->client_ip, task->size, task->length);

                    ioevent_add_to_deleted_list(task);
                    return -1;
                }

                logDebug("file: "__FILE__", line: %d, "
                        "client ip: %s, task length: %d, realloc buffer size "
                        "from %d to %d", __LINE__, task->client_ip,
                        task->length, old_size, task->size);
            }
        }

        if (task->offset >= task->length) { //recv done
            task->req_count++;
            task->nio_stages.current = SF_NIO_STAGE_SEND;
            if (SF_CTX->deal_task(task, SF_NIO_STAGE_SEND) < 0) {  //fatal error
                ioevent_add_to_deleted_list(task);
                return -1;
            }
            break;
        }
    }

    return total_read;
}

int sf_client_sock_write(int sock, short event, void *arg)
{
    int result;
    int bytes;
    int total_write;
    struct fast_task_info *task;

    task = (struct fast_task_info *)arg;
    if ((result=check_task(task, event, SF_NIO_STAGE_SEND)) != 0) {
        return result >= 0 ? 0 : -1;
    }

    if (event & IOEVENT_TIMEOUT) {
        logError("file: "__FILE__", line: %d, "
            "client ip: %s, send timeout. total length: %d, offset: %d, "
            "remain: %d", __LINE__, task->client_ip, task->length,
            task->offset, task->length - task->offset);

        ioevent_add_to_deleted_list(task);
        return -1;
    }

    total_write = 0;
    while (1) {
        fast_timer_modify(&task->thread_data->timer,
            &task->event.timer, g_current_time +
            task->network_timeout);

        if (task->iovec_array.iovs != NULL) {
            bytes = writev(sock, task->iovec_array.iovs,
                    FC_MIN(task->iovec_array.count, IOV_MAX));
        } else {
            bytes = write(sock, task->data + task->offset,
                    task->length - task->offset);
        }
        if (bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                if (set_write_event(task) != 0) {
                    return -1;
                }
                break;
            } else if (errno == EINTR) {  //should retry
                logDebug("file: "__FILE__", line: %d, "
                    "client ip: %s, ignore interupt signal",
                    __LINE__, task->client_ip);
                continue;
            } else {
                logWarning("file: "__FILE__", line: %d, "
                    "client ip: %s, send fail, "
                    "errno: %d, error info: %s",
                    __LINE__, task->client_ip,
                    errno, strerror(errno));

                ioevent_add_to_deleted_list(task);
                return -1;
            }
        } else if (bytes == 0) {
            logWarning("file: "__FILE__", line: %d, "
                "client ip: %s, sock: %d, send failed, "
                "connection disconnected",
                __LINE__, task->client_ip, sock);

            ioevent_add_to_deleted_list(task);
            return -1;
        }

        total_write += bytes;
        task->offset += bytes;
        if (task->offset >= task->length) {
            release_iovec_buffer(task);

            task->offset = 0;
            task->length = 0;
            if (sf_set_read_event(task) != 0) {
                return -1;
            }
            break;
        }

        /* set next writev iovec array */
        if (task->iovec_array.iovs != NULL) {
            struct iovec *iov;
            struct iovec *end;
            int iov_sum;
            int iov_remain;

            iov = task->iovec_array.iovs;
            end = task->iovec_array.iovs + task->iovec_array.count;
            iov_sum = 0;
            do {
                iov_sum += iov->iov_len;
                iov_remain = iov_sum - bytes;
                if (iov_remain == 0) {
                    iov++;
                    break;
                } else if (iov_remain > 0) {
                    iov->iov_base += (iov->iov_len - iov_remain);
                    iov->iov_len = iov_remain;
                    break;
                }

                iov++;
            } while (iov < end);

            task->iovec_array.iovs = iov;
            task->iovec_array.count = end - iov;
        }
    }

    return total_write;
}
