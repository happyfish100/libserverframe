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
#include "fastcommon/fc_atomic.h"
#include "sf_service.h"
#include "sf_nio.h"

static int sf_client_sock_write(int sock, const int event, void *arg);
static int sf_client_sock_read(int sock, const int event, void *arg);

void sf_set_parameters_ex(SFContext *sf_context, const int header_size,
        sf_set_body_length_callback set_body_length_func,
        sf_alloc_recv_buffer_callback alloc_recv_buffer_func,
        sf_send_done_callback send_done_callback,
        sf_deal_task_callback deal_func, TaskCleanUpCallback cleanup_func,
        sf_recv_timeout_callback timeout_callback, sf_release_buffer_callback
        release_buffer_callback)
{
    sf_context->header_size = header_size;
    sf_context->callbacks.set_body_length = set_body_length_func;
    sf_context->callbacks.alloc_recv_buffer = alloc_recv_buffer_func;
    sf_context->callbacks.send_done = send_done_callback;
    sf_context->callbacks.deal_task = deal_func;
    sf_context->callbacks.task_cleanup = cleanup_func;
    sf_context->callbacks.task_timeout = timeout_callback;
    sf_context->callbacks.release_buffer = release_buffer_callback;
}

#if IOEVENT_USE_URING
#define CLEAR_OP_TYPE_AND_RELEASE_TASK(task) \
    FC_URING_OP_TYPE(task) = IORING_OP_NOP;  \
    sf_release_task(task)

static int sf_uring_cancel_done(int sock, const int event, void *arg)
{
    struct fast_task_info *task;

    task = (struct fast_task_info *)arg;
    if (event != IOEVENT_TIMEOUT) {
        CLEAR_OP_TYPE_AND_RELEASE_TASK(task);
    }
    return 0;
}
#endif

void sf_task_detach_thread(struct fast_task_info *task)
{
#if IOEVENT_USE_URING
    bool need_cancel;
    if (task->handler->use_io_uring) {
        need_cancel = (FC_URING_OP_TYPE(task) != IORING_OP_NOP);
    } else {
        need_cancel = true;
    }
    if (need_cancel) {
        task->event.callback = (IOEventCallback)sf_uring_cancel_done;
        uring_prep_cancel(task);
    }
#else
    ioevent_detach(&task->thread_data->ev_puller, task->event.fd);
#endif

    if (task->event.timer.expires > 0) {
        fast_timer_remove(&task->thread_data->timer,
                &task->event.timer);
        task->event.timer.expires = 0;
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
        if (SF_CTX->callbacks.release_buffer != NULL) {
            SF_CTX->callbacks.release_buffer(task);
        }
        task->iovec_array.iovs = NULL;
        task->iovec_array.count = 0;
    }
}

void sf_socket_close_connection(struct fast_task_info *task)
{
#if IOEVENT_USE_URING
    if (task->handler->use_io_uring) {
        if (uring_prep_close_fd(task) != 0) {
            close(task->event.fd);
        }
    } else {
#endif
        close(task->event.fd);
#if IOEVENT_USE_URING
    }
#endif
    task->event.fd = -1;
}

void sf_task_finish_clean_up(struct fast_task_info *task)
{
    if (task->finish_callback != NULL) {
        task->finish_callback(task);
        task->finish_callback = NULL;
    }

    release_iovec_buffer(task);
    sf_task_detach_thread(task);

#if IOEVENT_USE_URING
    if (!task->handler->use_io_uring) {
#endif
        task->handler->close_connection(task);
        __sync_fetch_and_sub(&g_sf_global_vars.
                connection_stat.current_count, 1);

#if IOEVENT_USE_URING
    }
#endif

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
        logError("file: "__FILE__", line: %d, "
                "ioevent_modify fail, "
                "errno: %d, error info: %s",
                __LINE__, result, strerror(result));
        return result;
    }
    return 0;
}

#if IOEVENT_USE_URING
static inline int prepare_first_recv(struct fast_task_info *task)
{
    if (SF_CTX->callbacks.alloc_recv_buffer != NULL) {
        return uring_prep_recv_data(task, task->recv.ptr->data,
                SF_CTX->header_size);
    } else {
        return uring_prep_first_recv(task);
    }
}

static inline int prepare_next_recv(struct fast_task_info *task)
{
    int recv_bytes;

    if (task->recv.ptr->length == 0) { //recv header
        recv_bytes = SF_CTX->header_size - task->recv.ptr->offset;
        return uring_prep_recv_data(task, task->recv.ptr->data +
                task->recv.ptr->offset, recv_bytes);
    } else {
        recv_bytes = task->recv.ptr->length - task->recv.ptr->offset;
        if (task->recv_body == NULL) {
            return uring_prep_recv_data(task, task->recv.ptr->data +
                    task->recv.ptr->offset, recv_bytes);
        } else {
            return uring_prep_recv_data(task, task->recv_body +
                    (task->recv.ptr->offset - SF_CTX->
                     header_size), recv_bytes);
        }
    }
}
#endif

static inline int set_read_event(struct fast_task_info *task)
{
    int result;

#if IOEVENT_USE_URING
    if (task->handler->use_io_uring) {
        if (FC_URING_OP_TYPE(task) != IORING_OP_NOP) {
            if (FC_URING_OP_TYPE(task) == IORING_OP_RECV) {
                logWarning("file: "__FILE__", line: %d, "
                        "trigger recv again!", __LINE__);
                return 0;
            } else {
                logWarning("file: "__FILE__", line: %d, "
                        "another operation in progress, op_type: %d!",
                        __LINE__, FC_URING_OP_TYPE(task));
                return EBUSY;
            }
        }

        if (task->event.callback != (IOEventCallback)sf_client_sock_read) {
            task->event.callback = (IOEventCallback)sf_client_sock_read;
        }
        if ((result=prepare_first_recv(task)) != 0) {
            ioevent_add_to_deleted_list(task);
            return result;
        }
    } else {
#endif

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

#if IOEVENT_USE_URING
    }
#endif

    return 0;
}

int sf_set_read_event(struct fast_task_info *task)
{
#if IOEVENT_USE_URING
    if (task->handler->use_io_uring) {
        return 0;
    }
#endif

    /* reset recv offset and length */
    task->recv.ptr->offset = 0;
    task->recv.ptr->length = 0;

    task->nio_stages.current = SF_NIO_STAGE_RECV;
    return set_read_event(task);
}

static inline int sf_ioevent_add(struct fast_task_info *task)
{
    int result;

    result = ioevent_set(task, task->thread_data, task->event.fd,
            IOEVENT_READ, (IOEventCallback)sf_client_sock_read,
            SF_CTX->net_buffer_cfg.network_timeout,
            task->handler->use_io_uring);
    return result > 0 ? -1 * result : result;
}

static inline void inc_connection_current_count()
{
    int current_connections;

    current_connections = FC_ATOMIC_INC(g_sf_global_vars.
            connection_stat.current_count);
    if (current_connections > g_sf_global_vars.connection_stat.max_count) {
        g_sf_global_vars.connection_stat.max_count = current_connections;
    }
}

static inline int sf_nio_init(struct fast_task_info *task)
{
    inc_connection_current_count();
    return sf_ioevent_add(task);
}

int sf_socket_async_connect_check(struct fast_task_info *task)
{
    int result;
    socklen_t len;

    len = sizeof(result);
    if (getsockopt(task->event.fd, SOL_SOCKET, SO_ERROR, &result, &len) < 0) {
        result = errno != 0 ? errno : EACCES;
    }
    return result;
}

static int sf_client_connect_done(int sock, const int event, void *arg)
{
    int result;
    struct fast_task_info *task;
    char formatted_ip[FORMATTED_IP_SIZE];

    task = (struct fast_task_info *)arg;
    if (task->canceled) {
#if IOEVENT_USE_URING
        if (task->handler->use_io_uring && event != IOEVENT_TIMEOUT) {
            CLEAR_OP_TYPE_AND_RELEASE_TASK(task);
        }
#endif
        return ENOTCONN;
    }

    if (event == IOEVENT_TIMEOUT) {
        result = ETIMEDOUT;
    } else {
#if IOEVENT_USE_URING
        if (task->handler->use_io_uring) {
            CLEAR_OP_TYPE_AND_RELEASE_TASK(task);
            result = (task->event.res < 0 ? -1 * task->event.res :
                    task->event.res);
        } else {
#endif
            result = task->handler->async_connect_check(task);
            if (result == EINPROGRESS) {
                return 0;
            }
#if IOEVENT_USE_URING
        }
#endif
    }

    if (SF_CTX->callbacks.connect_done != NULL) {
        SF_CTX->callbacks.connect_done(task, result);
    }

    if (result != 0) {
        if (SF_CTX->connect_need_log) {
            format_ip_address(task->server_ip, formatted_ip);
            logError("file: "__FILE__", line: %d, "
                    "connect to server %s:%u fail, errno: %d, "
                    "error info: %s", __LINE__, formatted_ip,
                    task->port, result, STRERROR(result));
        }
        ioevent_add_to_deleted_list(task);
        return -1;
    }

    if (SF_CTX->connect_need_log) {
        format_ip_address(task->server_ip, formatted_ip);
        logInfo("file: "__FILE__", line: %d, "
                "connect to server %s:%u successfully",
                __LINE__, formatted_ip, task->port);
    }
    return SF_CTX->callbacks.deal_task(task, SF_NIO_STAGE_HANDSHAKE);
}

int sf_socket_async_connect_server(struct fast_task_info *task)
{
    int result;

#if IOEVENT_USE_URING
    if (task->handler->use_io_uring) {
        if ((result=uring_prep_connect(task)) != 0) {
            return result;
        }
        return EINPROGRESS;
    } else {
#endif
        if ((task->event.fd=socketCreateEx2(AF_UNSPEC, task->server_ip,
                        O_NONBLOCK, NULL, &result)) < 0)
        {
            return result > 0 ? -1 * result : result;
        }

        return asyncconnectserverbyip(task->event.fd,
                task->server_ip, task->port);
#if IOEVENT_USE_URING
    }
#endif
}

static int sf_async_connect_server(struct fast_task_info *task)
{
    int result;
    char formatted_ip[FORMATTED_IP_SIZE];

    if ((result=task->handler->async_connect_server(task)) == EINPROGRESS) {
        result = ioevent_set(task, task->thread_data, task->event.fd,
                IOEVENT_READ | IOEVENT_WRITE, (IOEventCallback)
                sf_client_connect_done, SF_CTX->net_buffer_cfg.
                connect_timeout, task->handler->use_io_uring);
        return result > 0 ? -1 * result : result;
    } else {
        if (SF_CTX->callbacks.connect_done != NULL) {
            SF_CTX->callbacks.connect_done(task, result);
        }

        if (result == 0) {
            if ((result=sf_ioevent_add(task)) != 0) {
                return result;
            }

            if (SF_CTX->connect_need_log) {
                format_ip_address(task->server_ip, formatted_ip);
                logInfo("file: "__FILE__", line: %d, "
                        "connect to server %s:%u successfully",
                        __LINE__, formatted_ip, task->port);
            }
            return SF_CTX->callbacks.deal_task(task, SF_NIO_STAGE_HANDSHAKE);
        } else {
            task->handler->close_connection(task);
            if (SF_CTX->connect_need_log) {
                format_ip_address(task->server_ip, formatted_ip);
                logError("file: "__FILE__", line: %d, "
                        "connect to server %s:%u fail, errno: %d, "
                        "error info: %s", __LINE__, formatted_ip,
                        task->port, result, STRERROR(result));
            }
            return result > 0 ? -1 * result : result;
        }
    }
}

static int sf_nio_deal_task(struct fast_task_info *task, const int stage)
{
    int result;

    switch (stage) {
        case SF_NIO_STAGE_INIT:    //for server init
            task->nio_stages.current = SF_NIO_STAGE_RECV;
            result = sf_nio_init(task);
            break;
        case SF_NIO_STAGE_CONNECT:  //for client init
            inc_connection_current_count();
            result = sf_async_connect_server(task);
            break;
        case SF_NIO_STAGE_RECV:
            task->nio_stages.current = SF_NIO_STAGE_RECV;
            if ((result=set_read_event(task)) == 0) {
                if (!task->handler->use_io_uring) {
                    if (sf_client_sock_read(task->event.fd,
                                IOEVENT_READ, task) < 0)
                    {
                        result = errno != 0 ? errno : EIO;
                    }
                }
            }
            break;
        case SF_NIO_STAGE_SEND:
            result = sf_send_add_event(task);
            break;
        case SF_NIO_STAGE_CONTINUE:   //continue deal
            result = SF_CTX->callbacks.deal_task(task, SF_NIO_STAGE_CONTINUE);
            break;
        case SF_NIO_STAGE_FORWARDED:  //forward by other thread
            if ((result=sf_ioevent_add(task)) == 0) {
                result = SF_CTX->callbacks.deal_task(task, SF_NIO_STAGE_SEND);
            }
            break;
        case SF_NIO_STAGE_CLOSE:
            result = -EIO;   //close this socket
            break;
        default:
            logError("file: "__FILE__", line: %d, "
                    "client ip: %s, task: %p, sock: %d, invalid notify stage: %d",
                    __LINE__, task->client_ip, task, task->event.fd, stage);
            result = -EINVAL;
            break;
    }

    if (result < 0) {
        ioevent_add_to_deleted_list(task);
    } else if (result > 0) {
        if (stage == SF_NIO_STAGE_RECV || stage == SF_NIO_STAGE_SEND) {
            return -1 * result;
        }
    }

    return result;
}

int sf_nio_notify(struct fast_task_info *task, const int stage)
{
    int64_t n;
    int result;
    int old_stage;
    bool notify;

    if (FC_ATOMIC_GET(task->canceled)) {
        if (stage == SF_NIO_STAGE_CONTINUE) {
            if (task->continue_callback != NULL) {
                return task->continue_callback(task);
            } else {
                logDebug("file: "__FILE__", line: %d, "
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
        old_stage = FC_ATOMIC_GET(task->nio_stages.notify);
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
    task->notify_next = NULL;
    if (task->thread_data->waiting_queue.tail == NULL) {
        task->thread_data->waiting_queue.head = task;
        notify = true;
    } else {
        task->thread_data->waiting_queue.tail->notify_next = task;
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
                    "write to fd %d fail, errno: %d, error info: %s",
                    __LINE__, FC_NOTIFY_WRITE_FD(task->thread_data),
                    result, STRERROR(result));
            return result;
        }
    }

    return 0;
}

static inline void deal_notified_task(struct fast_task_info *task,
        const int stage)
{
    if (!task->canceled) {
        sf_nio_deal_task(task, stage);
    } else {
        if (stage == SF_NIO_STAGE_CONTINUE) {
            if (task->continue_callback != NULL) {
                task->continue_callback(task);
            } else {
                logWarning("file: "__FILE__", line: %d, "
                        "task %p, continue_callback is NULL",
                        __LINE__, task);
            }
        }
    }
}

void sf_recv_notify_read(int fd, const int event, void *arg)
{
    int64_t n;
    int stage;
    struct ioevent_notify_entry *notify_entry;
    struct fast_task_info *task;
    struct fast_task_info *current;

    notify_entry = (struct ioevent_notify_entry *)arg;
    if (read(fd, &n, sizeof(n)) < 0) {
#if IOEVENT_USE_URING
        if (errno == EAGAIN) {
            return;
        }
#endif

        logWarning("file: "__FILE__", line: %d, "
                "read from fd %d fail, errno: %d, error info: %s",
                __LINE__, fd, errno, STRERROR(errno));
    }

    PTHREAD_MUTEX_LOCK(&notify_entry->thread_data->waiting_queue.lock);
    current = notify_entry->thread_data->waiting_queue.head;
    notify_entry->thread_data->waiting_queue.head = NULL;
    notify_entry->thread_data->waiting_queue.tail = NULL;
    PTHREAD_MUTEX_UNLOCK(&notify_entry->thread_data->waiting_queue.lock);

    while (current != NULL) {
        task = current;
        current = current->notify_next;

        stage = FC_ATOMIC_GET(task->nio_stages.notify);
        if (stage == SF_NIO_STAGE_CONTINUE || SF_G_EPOLL_EDGE_TRIGGER) {
            /* MUST set to SF_NIO_STAGE_NONE first for re-entry */
            __sync_bool_compare_and_swap(&task->nio_stages.notify,
                    stage, SF_NIO_STAGE_NONE);
            deal_notified_task(task, stage);
        } else {
            deal_notified_task(task, stage);
            __sync_bool_compare_and_swap(&task->nio_stages.notify,
                    stage, SF_NIO_STAGE_NONE);
        }
    }
}

int sf_send_add_event(struct fast_task_info *task)
{
    task->send.ptr->offset = 0;
    if (task->send.ptr->length > 0) {
        /* direct send */
        task->nio_stages.current = SF_NIO_STAGE_SEND;
#if IOEVENT_USE_URING
        if (task->handler->use_io_uring) {
            if (task->event.callback != (IOEventCallback)sf_client_sock_write) {
                task->event.callback = (IOEventCallback)sf_client_sock_write;
            }
            if (task->handler->use_send_zc) {
                return uring_prep_first_send_zc(task);
            } else {
                return uring_prep_first_send(task);
            }
        } else {
#endif
            if (sf_client_sock_write(task->event.fd, IOEVENT_WRITE, task) < 0) {
                return errno != 0 ? errno : EIO;
            }
#if IOEVENT_USE_URING
        }
#endif
    }

    return 0;
}

static inline int check_task(struct fast_task_info *task,
        const int event, const int expect_stage)
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

    if (task->nio_stages.current == expect_stage) {
        return 0;
    }

#if IOEVENT_USE_URING
    if (task->handler->use_io_uring) {
        logWarning("file: "__FILE__", line: %d, "
                "client ip: %s, event: %d, expect stage: %d, "
                "but current stage: %d, close connection",
                __LINE__, task->client_ip, event,
                expect_stage, task->nio_stages.current);
        ioevent_add_to_deleted_list(task);
        return -1;
    }
#endif

    if (task->handler->comm_type == fc_comm_type_sock) {
        if (tcp_socket_connected(task->event.fd)) {
            return EAGAIN;
        } else {
            logDebug("file: "__FILE__", line: %d, "
                    "client ip: %s, connection is closed",
                    __LINE__, task->client_ip);

            ioevent_add_to_deleted_list(task);
            return -1;
        }
    } else {
        return EAGAIN;
    }
}

#if IOEVENT_USE_URING
static inline int prepare_next_send(struct fast_task_info *task)
{
    if (task->handler->use_send_zc) {
        return uring_prep_next_send_zc(task);
    } else {
        return uring_prep_next_send(task);
    }
}
#endif

ssize_t sf_socket_send_data(struct fast_task_info *task,
        SFCommAction *action, bool *send_done)
{
    int bytes;
    int result;

#if IOEVENT_USE_URING
    if (task->handler->use_io_uring) {
        bytes = task->event.res;
    } else {
#endif
        if (task->iovec_array.iovs != NULL) {
            bytes = writev(task->event.fd, task->iovec_array.iovs,
                    FC_MIN(task->iovec_array.count, IOV_MAX));
        } else {
            bytes = write(task->event.fd, task->send.ptr->data +
                    task->send.ptr->offset, task->send.ptr->length -
                    task->send.ptr->offset);
        }
#if IOEVENT_USE_URING
    }
#endif

    if (bytes < 0) {
#if IOEVENT_USE_URING
        if (task->handler->use_io_uring) {
            result = -bytes;
        } else {
#endif
            result = errno;
#if IOEVENT_USE_URING
        }
#endif
        if (result == EAGAIN || result == EWOULDBLOCK) {
#if IOEVENT_USE_URING
            if (task->handler->use_io_uring) {
                if (prepare_next_send(task) != 0) {
                    return -1;
                }
            } else {
#endif
                if (set_write_event(task) != 0) {
                    return -1;
                }
#if IOEVENT_USE_URING
            }
#endif

            *action = sf_comm_action_break;
            return 0;
        } else if (result == EINTR && !task->handler->use_io_uring) {
            /* should try again */
            logDebug("file: "__FILE__", line: %d, "
                    "client ip: %s, ignore interupt signal",
                    __LINE__, task->client_ip);
            *action = sf_comm_action_continue;
            return 0;
        } else {
            logWarning("file: "__FILE__", line: %d, "
                    "client ip: %s, send fail, task offset: %d, length: %d, "
                    "errno: %d, error info: %s", __LINE__, task->client_ip,
                    task->send.ptr->offset, task->send.ptr->length,
                    result, strerror(result));
            return -1;
        }
    } else if (bytes == 0) {
        logWarning("file: "__FILE__", line: %d, "
                "client ip: %s, task length: %d, offset: %d, "
                "send failed, connection disconnected", __LINE__,
                task->client_ip, task->send.ptr->length,
                task->send.ptr->offset);
        return -1;
    }

    task->send.ptr->offset += bytes;
    if (task->send.ptr->offset >= task->send.ptr->length) {
#if IOEVENT_USE_URING
        if (FC_URING_IS_SEND_ZC(task) && task->thread_data->
                ev_puller.send_zc_done_notify)
        {
            *action = sf_comm_action_break;
            *send_done = false;
        } else {
#endif
            if (task->send.ptr != task->recv.ptr) {  //double buffers
                task->send.ptr->offset = 0;
                task->send.ptr->length = 0;
            }

            *action = sf_comm_action_finish;
            *send_done = true;
#if IOEVENT_USE_URING
        }
#endif

    } else {
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

#if IOEVENT_USE_URING
        if (task->handler->use_io_uring) {
            if (!(FC_URING_IS_SEND_ZC(task) && task->thread_data->
                        ev_puller.send_zc_done_notify))
            {
                if (prepare_next_send(task) != 0) {
                    return -1;
                }
            }
            *action = sf_comm_action_break;
        } else {
#endif
            *action = sf_comm_action_continue;
#if IOEVENT_USE_URING
        }
#endif

        *send_done = false;
    }

    return bytes;
}

ssize_t sf_socket_recv_data(struct fast_task_info *task,
        const bool call_post_recv, SFCommAction *action)
{
    int bytes;
    int result;
    int recv_bytes;
    bool new_alloc;

#if IOEVENT_USE_URING
    if (task->handler->use_io_uring) {
        bytes = task->event.res;
    } else {
#endif
        if (task->recv.ptr->length == 0) { //recv header
            recv_bytes = SF_CTX->header_size - task->recv.ptr->offset;
            bytes = read(task->event.fd, task->recv.ptr->data +
                    task->recv.ptr->offset, recv_bytes);
        } else {
            recv_bytes = task->recv.ptr->length - task->recv.ptr->offset;
            if (task->recv_body == NULL) {
                bytes = read(task->event.fd, task->recv.ptr->data +
                        task->recv.ptr->offset, recv_bytes);
            } else {
                bytes = read(task->event.fd, task->recv_body +
                        (task->recv.ptr->offset - SF_CTX->
                         header_size), recv_bytes);
            }
        }
#if IOEVENT_USE_URING
    }
#endif

    if (bytes < 0) {
#if IOEVENT_USE_URING
        if (task->handler->use_io_uring) {
            result = -bytes;
        } else {
#endif
            result = errno;
#if IOEVENT_USE_URING
        }
#endif
        if (result == EAGAIN || result == EWOULDBLOCK) {
#if IOEVENT_USE_URING
            if (task->handler->use_io_uring) {
                if (prepare_next_recv(task) != 0) {
                    return -1;
                }
            }
#endif
            *action = sf_comm_action_break;
            return 0;
        } else if (result == EINTR && !task->handler->use_io_uring) {
            /* should try again */
            logDebug("file: "__FILE__", line: %d, "
                    "client ip: %s, ignore interupt signal",
                    __LINE__, task->client_ip);
            *action = sf_comm_action_continue;
            return 0;
        } else {
            logWarning("file: "__FILE__", line: %d, "
                    "client ip: %s, recv fail, "
                    "errno: %d, error info: %s",
                    __LINE__, task->client_ip,
                    result, strerror(result));
            return -1;
        }
    } else if (bytes == 0) {
        if (task->recv.ptr->offset > 0) {
            if (task->recv.ptr->length > 0) {
                logWarning("file: "__FILE__", line: %d, "
                        "client ip: %s, connection disconnected, "
                        "expect pkg length: %d, recv pkg length: %d",
                        __LINE__, task->client_ip, task->recv.ptr->length,
                        task->recv.ptr->offset);
            } else {
                logWarning("file: "__FILE__", line: %d, "
                        "client ip: %s, connection "
                        "disconnected, recv pkg length: %d",
                        __LINE__, task->client_ip,
                        task->recv.ptr->offset);
            }
        } else {
            logDebug("file: "__FILE__", line: %d, "
                    "client ip: %s, sock: %d, recv fail, "
                    "connection disconnected", __LINE__,
                    task->client_ip, task->event.fd);
        }

        return -1;
    }

    TCP_SET_QUICK_ACK(task->event.fd);
    task->recv.ptr->offset += bytes;
    if (task->recv.ptr->length == 0) { //pkg header
        if (task->recv.ptr->offset < SF_CTX->header_size) {
#if IOEVENT_USE_URING
            if (task->handler->use_io_uring) {
                if (prepare_next_recv(task) != 0) {
                    return -1;
                }
                *action = sf_comm_action_break;
            } else {
#endif
                *action = sf_comm_action_continue;
#if IOEVENT_USE_URING
            }
#endif
            return bytes;
        }

        if (sf_set_body_length(task) != 0) {
            return -1;
        }

        if (SF_CTX->callbacks.alloc_recv_buffer != NULL) {
            task->recv_body = SF_CTX->callbacks.alloc_recv_buffer(task,
                    task->recv.ptr->length - SF_CTX->header_size, &new_alloc);
            if (new_alloc && task->recv_body == NULL) {
                return -1;
            }
        } else {
            new_alloc = false;
        }

        if (!new_alloc) {
            if (task->recv.ptr->length > task->recv.ptr->size) {
                int old_size;

                if (!SF_CTX->realloc_task_buffer) {
                    logError("file: "__FILE__", line: %d, "
                            "client ip: %s, pkg length: %d exceeds "
                            "task size: %d, but realloc buffer disabled",
                            __LINE__, task->client_ip, task->recv.ptr->size,
                            task->recv.ptr->length);
                    return -1;
                }

                old_size = task->recv.ptr->size;
                if (free_queue_realloc_recv_buffer(task, task->
                            recv.ptr->length) != 0)
                {
                    logError("file: "__FILE__", line: %d, "
                            "client ip: %s, realloc buffer size from %d "
                            "to %d fail", __LINE__, task->client_ip,
                            task->recv.ptr->size, task->recv.ptr->length);
                    return -1;
                }

                logDebug("file: "__FILE__", line: %d, "
                        "client ip: %s, task length: %d, realloc buffer "
                        "size from %d to %d", __LINE__, task->client_ip,
                        task->recv.ptr->length, old_size, task->recv.ptr->size);
            }
        }
    }

    if (task->recv.ptr->offset >= task->recv.ptr->length) { //recv done
        *action = sf_comm_action_finish;
    } else {
#if IOEVENT_USE_URING
        if (task->handler->use_io_uring) {
            if (prepare_next_recv(task) != 0) {
                return -1;
            }
            *action = sf_comm_action_break;
        } else {
#endif
            *action = sf_comm_action_continue;
#if IOEVENT_USE_URING
        }
#endif
    }

    return bytes;
}

static int calc_iops_and_trigger_polling(struct fast_task_info *task)
{
    char formatted_ip[FORMATTED_IP_SIZE];
    int time_distance;
    int result = 0;

    time_distance = g_current_time - task->polling.last_calc_time;
    if (time_distance > 0) {
        if ((task->req_count - task->polling.last_req_count) /
                time_distance >= SF_CTX->smart_polling.switch_on_iops)
        {
            task->polling.continuous_count++;
            if (task->polling.continuous_count >= SF_CTX->
                    smart_polling.switch_on_count)
            {
                task->polling.continuous_count = 0;
                task->polling.in_queue = true;
                result = ioevent_detach(&task->thread_data->
                        ev_puller, task->event.fd);
                fast_timer_remove(&task->thread_data->timer,
                        &task->event.timer);

                if (fc_list_empty(&task->thread_data->polling_queue)) {
                    ioevent_set_timeout(&task->thread_data->
                            ev_puller, 0);
                }
                fc_list_add_tail(&task->polling.dlink,
                        &task->thread_data->polling_queue);

                format_ip_address(task->client_ip, formatted_ip);
                logInfo("file: "__FILE__", line: %d, client: %s:%u, "
                        "trigger polling iops: %"PRId64, __LINE__,
                        formatted_ip, task->port, (task->req_count -
                            task->polling.last_req_count) / time_distance);
            }
        } else {
            if (task->polling.continuous_count > 0) {
                task->polling.continuous_count = 0;
            }
        }

        task->polling.last_calc_time = g_current_time;
        task->polling.last_req_count = task->req_count;
    }

    return result;
}

static int calc_iops_and_remove_polling(struct fast_task_info *task)
{
    char formatted_ip[FORMATTED_IP_SIZE];
    int time_distance;
    int result = 0;

    time_distance = g_current_time - task->polling.last_calc_time;
    if (time_distance > 0) {
        if ((task->req_count - task->polling.last_req_count) /
                time_distance < SF_CTX->smart_polling.switch_on_iops)
        {
            task->polling.continuous_count++;
            if (task->polling.continuous_count >= SF_CTX->
                    smart_polling.switch_on_count)
            {
                task->polling.continuous_count = 0;
                task->polling.in_queue = false;
                fc_list_del_init(&task->polling.dlink);
                if (fc_list_empty(&task->thread_data->polling_queue)) {
                    ioevent_set_timeout(&task->thread_data->ev_puller,
                            task->thread_data->timeout_ms);
                }
                result = sf_ioevent_add(task);

                format_ip_address(task->client_ip, formatted_ip);
                logInfo("file: "__FILE__", line: %d, client: %s:%u, "
                        "remove polling iops: %"PRId64, __LINE__,
                        formatted_ip, task->port, (task->req_count -
                            task->polling.last_req_count) / time_distance);
            }
        } else {
            if (task->polling.continuous_count > 0) {
                task->polling.continuous_count = 0;
            }
        }

        task->polling.last_calc_time = g_current_time;
        task->polling.last_req_count = task->req_count;
    }

    return result;
}

int sf_rdma_busy_polling_callback(struct nio_thread_data *thread_data)
{
    struct fast_task_info *task;
    struct fast_task_info *tmp;
    int bytes;
    SFCommAction action;

    fc_list_for_each_entry_safe(task, tmp, &thread_data->
            polling_queue, polling.dlink)
    {
        if (task->canceled) {
            continue;
        }
        if ((bytes=task->handler->recv_data(task, !task->handler->
                        explicit_post_recv, &action)) < 0)
        {
            ioevent_add_to_deleted_list(task);
            continue;
        }

        if (action == sf_comm_action_finish) {
            task->req_count++;
            task->nio_stages.current = SF_NIO_STAGE_SEND;
            if (SF_CTX->callbacks.deal_task(task, SF_NIO_STAGE_SEND) < 0) {
                /* fatal error */
                ioevent_add_to_deleted_list(task);
            } else if (task->handler->explicit_post_recv) {
                if (task->handler->post_recv(task) != 0) {
                    ioevent_add_to_deleted_list(task);
                }
            }
        } else {
            if (calc_iops_and_remove_polling(task) != 0) {
                ioevent_add_to_deleted_list(task);
            }
        }
    }

    return 0;
}

static int sf_client_sock_read(int sock, const int event, void *arg)
{
    int result;
    int bytes;
    int total_read;
    SFCommAction action;
    struct fast_task_info *task;

    task = (struct fast_task_info *)arg;
    if ((result=check_task(task, event, SF_NIO_STAGE_RECV)) != 0) {
#if IOEVENT_USE_URING
        if (task->handler->use_io_uring && event != IOEVENT_TIMEOUT) {
            CLEAR_OP_TYPE_AND_RELEASE_TASK(task);
        }
#endif
        return result >= 0 ? 0 : -1;
    }

    if (event == IOEVENT_TIMEOUT) {
        if (task->recv.ptr->offset == 0 && task->req_count > 0) {
            if (SF_CTX->callbacks.task_timeout != NULL) {
                if (SF_CTX->callbacks.task_timeout(task) != 0) {
                    ioevent_add_to_deleted_list(task);
                    return -1;
                }
            }

            task->event.timer.expires = g_current_time +
                SF_CTX->net_buffer_cfg.network_timeout;
            fast_timer_add(&task->thread_data->timer,
                    &task->event.timer);
            return 0;
        } else {
            if (task->recv.ptr->length > 0) {
                logWarning("file: "__FILE__", line: %d, "
                        "client ip: %s, recv timeout, recv "
                        "offset: %d, expect length: %d", __LINE__,
                        task->client_ip, task->recv.ptr->offset,
                        task->recv.ptr->length);
            } else {
                logWarning("file: "__FILE__", line: %d, "
                        "client ip: %s, req_count: %"PRId64", recv timeout",
                        __LINE__, task->client_ip,  task->req_count);
            }

            ioevent_add_to_deleted_list(task);
            return -1;
        }
    }

#if IOEVENT_USE_URING
    if (task->handler->use_io_uring) {
        CLEAR_OP_TYPE_AND_RELEASE_TASK(task);
    }
#endif

    total_read = 0;
    action = sf_comm_action_continue;
    while (1) {
        fast_timer_modify(&task->thread_data->timer,
            &task->event.timer, g_current_time +
            SF_CTX->net_buffer_cfg.network_timeout);

        if ((bytes=task->handler->recv_data(task, !task->handler->
                        explicit_post_recv, &action)) < 0)
        {
            ioevent_add_to_deleted_list(task);
            return -1;
        }

        total_read += bytes;
        if (action == sf_comm_action_finish) {
            task->req_count++;
            task->nio_stages.current = SF_NIO_STAGE_SEND;
            if (SF_CTX->callbacks.deal_task(task, SF_NIO_STAGE_SEND) < 0) {
                ioevent_add_to_deleted_list(task);
                return -1;
            }

            if (task->handler->explicit_post_recv) {
                if (task->handler->post_recv(task) != 0) {
                    ioevent_add_to_deleted_list(task);
                    return -1;
                }
            }

            if (SF_CTX->smart_polling.enabled) {
                if (calc_iops_and_trigger_polling(task) != 0) {
                    ioevent_add_to_deleted_list(task);
                    return -1;
                }
            }

            break;
        } else if (action == sf_comm_action_break) {
            break;
        }
    }

    return total_read;
}

static int sock_write_done(struct fast_task_info *task,
        const int length, const bool send_done)
{
    int next_stage;

    release_iovec_buffer(task);
    task->recv.ptr->offset = 0;
    task->recv.ptr->length = 0;

    if (SF_CTX->callbacks.send_done == NULL || !send_done) {
        task->nio_stages.current = SF_NIO_STAGE_RECV;
    } else {
        if (SF_CTX->callbacks.send_done(task,
                    length, &next_stage) != 0)
        {
            return -1;
        }

        if (task->nio_stages.current != next_stage) {
            task->nio_stages.current = next_stage;
        }
    }

#if IOEVENT_USE_URING
    if (!task->handler->use_io_uring || task->nio_stages.
            current == SF_NIO_STAGE_RECV)
    {
#endif

        if (set_read_event(task) != 0) {
            return -1;
        }

#if IOEVENT_USE_URING
    }
#endif

    return 0;
}

static int sf_client_sock_write(int sock, const int event, void *arg)
{
    int result;
    int bytes;
    int total_write;
    int length;
    SFCommAction action;
    bool send_done;
    struct fast_task_info *task;

    task = (struct fast_task_info *)arg;
    if ((result=check_task(task, event, SF_NIO_STAGE_SEND)) != 0) {
#if IOEVENT_USE_URING
        if (task->handler->use_io_uring && event != IOEVENT_TIMEOUT) {
            if (event == IOEVENT_NOTIFY || !(FC_URING_IS_SEND_ZC(task) &&
                        task->thread_data->ev_puller.send_zc_done_notify))
            {
                CLEAR_OP_TYPE_AND_RELEASE_TASK(task);
            }
        }
#endif
        return result >= 0 ? 0 : -1;
    }

    if (event == IOEVENT_TIMEOUT) {
        logError("file: "__FILE__", line: %d, "
            "client ip: %s, send timeout. total length: %d, offset: %d, "
            "remain: %d", __LINE__, task->client_ip, task->send.ptr->length,
            task->send.ptr->offset, task->send.ptr->length -
            task->send.ptr->offset);

        ioevent_add_to_deleted_list(task);
        return -1;
    }

#if IOEVENT_USE_URING
    if (event == IOEVENT_NOTIFY) {
        if (!FC_URING_IS_SEND_ZC(task)) {
            logWarning("file: "__FILE__", line: %d, "
                    "unexpected io_uring notify!", __LINE__);
            return -1;
        }

        FC_URING_OP_TYPE(task) = IORING_OP_NOP;
        if (!task->canceled) {
            if (task->send.ptr->offset >= task->send.ptr->length) {
                length = task->send.ptr->length;
                if (task->send.ptr != task->recv.ptr) {  //double buffers
                    task->send.ptr->offset = 0;
                    task->send.ptr->length = 0;
                }

                result = sock_write_done(task, length, true);
            } else {
                result = prepare_next_send(task);
            }
        }

        sf_release_task(task);
        return result == 0 ? 0 : -1;
    }

    if (task->handler->use_io_uring) {
        if (!(FC_URING_IS_SEND_ZC(task) && task->thread_data->
                    ev_puller.send_zc_done_notify))
        {
            CLEAR_OP_TYPE_AND_RELEASE_TASK(task);
        }
    }
#endif

    total_write = 0;
    length = task->send.ptr->length;
    action = sf_comm_action_continue;
    while (1) {
        fast_timer_modify(&task->thread_data->timer,
                &task->event.timer, g_current_time +
                SF_CTX->net_buffer_cfg.network_timeout);

        if ((bytes=task->handler->send_data(task, &action, &send_done)) < 0) {
            ioevent_add_to_deleted_list(task);
            return -1;
        }

        total_write += bytes;
        if (action == sf_comm_action_finish) {
            if (sock_write_done(task, length, send_done) != 0) {
                return -1;
            }
            break;
        } else if (action == sf_comm_action_break) {
            break;
        }
    }

    return total_write;
}
