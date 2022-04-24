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

//receipt_handler.c

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include "fastcommon/logger.h"
#include "fastcommon/sockopt.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/pthread_func.h"
#include "fastcommon/sched_thread.h"
#include "fastcommon/ioevent_loop.h"
#include "../../sf_util.h"
#include "../../sf_func.h"
#include "../../sf_nio.h"
#include "../../sf_global.h"
#include "../../sf_service.h"
#include "../../sf_proto.h"
#include "client_channel.h"
#include "receipt_handler.h"

static IdempotencyReceiptThreadContext *receipt_thread_contexts = NULL;

static int receipt_init_task(struct fast_task_info *task)
{
    task->connect_timeout = SF_G_CONNECT_TIMEOUT; //for client side
    task->network_timeout = SF_G_NETWORK_TIMEOUT;
    return 0;
}

static int receipt_recv_timeout_callback(struct fast_task_info *task)
{
    IdempotencyClientChannel *channel;

    if (SF_NIO_TASK_STAGE_FETCH(task) == SF_NIO_STAGE_CONNECT) {
        logError("file: "__FILE__", line: %d, "
                "connect to server %s:%u timeout",
                __LINE__, task->server_ip, task->port);
        return ETIMEDOUT;
    }

    channel = (IdempotencyClientChannel *)task->arg;
    if (channel->waiting_resp_qinfo.head != NULL) {
        logError("file: "__FILE__", line: %d, "
                "waiting receipt response from server %s:%u timeout",
                __LINE__, task->server_ip, task->port);
    } else {
        logError("file: "__FILE__", line: %d, "
                "communication with server %s:%u timeout, "
                "channel established: %d", __LINE__,
                task->server_ip, task->port,
                FC_ATOMIC_GET(channel->established));
    }

    return ETIMEDOUT;
}

static void receipt_task_finish_cleanup(struct fast_task_info *task)
{
    IdempotencyClientChannel *channel;

    if (task->event.fd >= 0) {
        sf_task_detach_thread(task);
        close(task->event.fd);
        task->event.fd = -1;
    }

    task->length = 0;
    task->offset = 0;
    task->req_count = 0;

    channel = (IdempotencyClientChannel *)task->arg;
    fc_list_del_init(&channel->dlink);
    __sync_bool_compare_and_swap(&channel->established, 1, 0);
    __sync_bool_compare_and_swap(&channel->in_ioevent, 1, 0);

    logDebug("file: "__FILE__", line: %d, "
            "receipt task for server %s:%u exit",
            __LINE__, task->server_ip, task->port);
}

static void setup_channel_request(struct fast_task_info *task)
{
    IdempotencyClientChannel *channel;
    SFCommonProtoHeader *header;
    SFProtoSetupChannelReq *req;

    channel = (IdempotencyClientChannel *)task->arg;
    header = (SFCommonProtoHeader *)task->data;
    req = (SFProtoSetupChannelReq *)(header + 1);
    int2buff(__sync_add_and_fetch(&channel->id, 0), req->channel_id);
    int2buff(__sync_add_and_fetch(&channel->key, 0), req->key);

    SF_PROTO_SET_HEADER(header, SF_SERVICE_PROTO_SETUP_CHANNEL_REQ,
            sizeof(SFProtoSetupChannelReq));
    task->length = sizeof(SFCommonProtoHeader) + sizeof(SFProtoSetupChannelReq);
    sf_send_add_event(task);
}

static int check_report_req_receipt(struct fast_task_info *task)
{
    IdempotencyClientChannel *channel;
    SFCommonProtoHeader *header;
    SFProtoReportReqReceiptHeader *rheader;
    SFProtoReportReqReceiptBody *rbody;
    SFProtoReportReqReceiptBody *rstart;
    IdempotencyClientReceipt *last;
    IdempotencyClientReceipt *receipt;
    char *buff_end;
    int count;

    channel = (IdempotencyClientChannel *)task->arg;
    if (channel->waiting_resp_qinfo.head != NULL) {
        return 0;
    }

    fc_queue_try_pop_to_queue(&channel->queue,
            &channel->waiting_resp_qinfo);
    if (channel->waiting_resp_qinfo.head == NULL) {
        return 0;
    }

    header = (SFCommonProtoHeader *)task->data;
    rheader = (SFProtoReportReqReceiptHeader *)(header + 1);
    rbody = rstart = (SFProtoReportReqReceiptBody *)(rheader + 1);
    buff_end = task->data + channel->buffer_size;
    last = NULL;
    receipt = channel->waiting_resp_qinfo.head;
    do {
        //check buffer remain space
        if (buff_end - (char *)rbody < sizeof(SFProtoReportReqReceiptBody)) {
            break;
        }

        long2buff(receipt->req_id, rbody->req_id);
        rbody++;

        last = receipt;
        receipt = receipt->next;
    } while (receipt != NULL);

    if (receipt != NULL) {  //repush to queue
        struct fc_queue_info qinfo;
        bool notify;

        qinfo.head = receipt;
        qinfo.tail = channel->waiting_resp_qinfo.tail;
        fc_queue_push_queue_to_head_ex(&channel->queue, &qinfo, &notify);

        last->next = NULL;
        channel->waiting_resp_qinfo.tail = last;
    }

    count = rbody - rstart;
    int2buff(count, rheader->count);
    task->length = (char *)rbody - task->data;
    int2buff(task->length - sizeof(SFCommonProtoHeader), header->body_len);
    header->cmd = SF_SERVICE_PROTO_REPORT_REQ_RECEIPT_REQ;
    sf_send_add_event(task);
    return count;
}

static void close_channel_request(struct fast_task_info *task)
{
    IdempotencyClientChannel *channel;
    SFCommonProtoHeader *header;

    channel = (IdempotencyClientChannel *)task->arg;
    idempotency_client_channel_set_id_key(channel, 0, 0);

    header = (SFCommonProtoHeader *)task->data;
    SF_PROTO_SET_HEADER(header, SF_SERVICE_PROTO_CLOSE_CHANNEL_REQ, 0);
    task->length = sizeof(SFCommonProtoHeader);
    sf_send_add_event(task);
}

static void active_test_request(struct fast_task_info *task)
{
    SFCommonProtoHeader *header;
    header = (SFCommonProtoHeader *)task->data;
    SF_PROTO_SET_HEADER(header, SF_PROTO_ACTIVE_TEST_REQ, 0);
    task->length = sizeof(SFCommonProtoHeader);
    sf_send_add_event(task);
}

static inline void update_lru_chain(struct fast_task_info *task)
{
    IdempotencyReceiptThreadContext *thread_ctx;
    IdempotencyClientChannel *channel;

    thread_ctx = (IdempotencyReceiptThreadContext *)task->thread_data->arg;
    channel = (IdempotencyClientChannel *)task->arg;
    channel->last_pkg_time = g_current_time;
    fc_list_move_tail(&channel->dlink, &thread_ctx->head);
}

static void report_req_receipt_request(struct fast_task_info *task,
        const bool update_lru)
{
    int count;

    if ((count=check_report_req_receipt(task)) == 0) {
        sf_set_read_event(task);  //trigger read event
    } else {
        ((IdempotencyClientChannel *)task->arg)->
            last_report_time = g_current_time;
        if (update_lru) {
            update_lru_chain(task);
        }
    }
}

static inline int receipt_expect_body_length(struct fast_task_info *task,
        const int expect_body_len)
{
    if ((int)(task->length - sizeof(SFCommonProtoHeader)) != expect_body_len) {
        logError("file: "__FILE__", line: %d, "
                "server %s:%u, response body length: %d != %d",
                __LINE__, task->server_ip, task->port, (int)(task->length -
                    sizeof(SFCommonProtoHeader)), expect_body_len);
        return EINVAL;
    }

    return 0;
}

static int deal_setup_channel_response(struct fast_task_info *task)
{
    int result;
    IdempotencyReceiptThreadContext *thread_ctx;
    SFProtoSetupChannelResp *resp;
    IdempotencyClientChannel *channel;
    int channel_id;
    int channel_key;
    int buffer_size;

    if ((result=receipt_expect_body_length(task,
                    sizeof(SFProtoSetupChannelResp))) != 0)
    {
        return result;
    }

    channel = (IdempotencyClientChannel *)task->arg;
    if (__sync_add_and_fetch(&channel->established, 0)) {
        logWarning("file: "__FILE__", line: %d, "
                "response from server %s:%u, unexpected cmd: "
                "SETUP_CHANNEL_RESP, ignore it!",
                __LINE__, task->server_ip, task->port);
        return 0;
    }

    resp = (SFProtoSetupChannelResp *)(task->data + sizeof(SFCommonProtoHeader));
    channel_id = buff2int(resp->channel_id);
    channel_key = buff2int(resp->key);
    buffer_size = buff2int(resp->buffer_size);
    idempotency_client_channel_set_id_key(channel, channel_id, channel_key);
    if (__sync_bool_compare_and_swap(&channel->established, 0, 1)) {
        thread_ctx = (IdempotencyReceiptThreadContext *)task->thread_data->arg;
        fc_list_add_tail(&channel->dlink, &thread_ctx->head);
    }
    channel->buffer_size = FC_MIN(buffer_size, task->size);

    PTHREAD_MUTEX_LOCK(&channel->lc_pair.lock);
    pthread_cond_broadcast(&channel->lc_pair.cond);
    PTHREAD_MUTEX_UNLOCK(&channel->lc_pair.lock);

    if (channel->waiting_resp_qinfo.head != NULL) {
        bool notify;
        fc_queue_push_queue_to_head_ex(&channel->queue,
                &channel->waiting_resp_qinfo, &notify);
        channel->waiting_resp_qinfo.head = NULL;
        channel->waiting_resp_qinfo.tail = NULL;
    }

    return 0;
}

static inline int deal_report_req_receipt_response(struct fast_task_info *task)
{
    int result;
    IdempotencyClientChannel *channel;
    IdempotencyClientReceipt *current;
    IdempotencyClientReceipt *deleted;

    if ((result=receipt_expect_body_length(task, 0)) != 0) {
        return result;
    }

    channel = (IdempotencyClientChannel *)task->arg;
    if (channel->waiting_resp_qinfo.head == NULL) {
        logWarning("file: "__FILE__", line: %d, "
                "response from server %s:%u, unexpect cmd: "
                "REPORT_REQ_RECEIPT_RESP", __LINE__,
                task->server_ip, task->port);
        return 0;
    }

    current = channel->waiting_resp_qinfo.head;
    do {
        deleted = current;
        current = current->next;

        fast_mblock_free_object(&channel->receipt_allocator, deleted);
    } while (current != NULL);

    channel->waiting_resp_qinfo.head = NULL;
    channel->waiting_resp_qinfo.tail = NULL;
    return 0;
}

static int receipt_deal_task(struct fast_task_info *task, const int stage)
{
    int result;

    do {
        if (stage == SF_NIO_STAGE_HANDSHAKE) {
            setup_channel_request(task);
            result = 0;
            break;
        } else if (stage == SF_NIO_STAGE_CONTINUE) {
            if (task->length == 0 && task->offset == 0) {
                if (((IdempotencyClientChannel *)task->arg)->established) {
                    report_req_receipt_request(task, true);
                } else if (task->req_count > 0) {
                    sf_set_read_event(task);  //trigger read event
                }
            }

            result = 0;
            break;
        }

        result = buff2short(((SFCommonProtoHeader *)task->data)->status);
        if (result != 0) {
            int msg_len;
            char *message;

            msg_len = task->length - sizeof(SFCommonProtoHeader);
            message = task->data + sizeof(SFCommonProtoHeader);
            logError("file: "__FILE__", line: %d, "
                    "response from server %s:%u, cmd: %d (%s), "
                    "status: %d, error info: %.*s",
                    __LINE__, task->server_ip, task->port,
                    ((SFCommonProtoHeader *)task->data)->cmd,
                    sf_get_cmd_caption(((SFCommonProtoHeader *)task->data)->cmd),
                    result, msg_len, message);
            break;
        }

        switch (((SFCommonProtoHeader *)task->data)->cmd) {
            case SF_SERVICE_PROTO_SETUP_CHANNEL_RESP:
                result = deal_setup_channel_response(task);
                break;
            case SF_SERVICE_PROTO_REPORT_REQ_RECEIPT_RESP:
                result = deal_report_req_receipt_response(task);
                break;
            case SF_PROTO_ACTIVE_TEST_RESP:
                result = 0;
                break;
            case SF_SERVICE_PROTO_CLOSE_CHANNEL_RESP:
                result = ECONNRESET; //force to close socket
                logDebug("file: "__FILE__", line: %d, "
                    "close channel to server %s:%u !!!",
                    __LINE__, task->server_ip, task->port);
                break;
            default:
                logError("file: "__FILE__", line: %d, "
                        "response from server %s:%u, unexpect cmd: %d (%s)",
                        __LINE__, task->server_ip, task->port,
                        ((SFCommonProtoHeader *)task->data)->cmd,
                        sf_get_cmd_caption(((SFCommonProtoHeader *)task->data)->cmd));
                result = EINVAL;
                break;
        }

        if (result == 0) {
            update_lru_chain(task);
            task->offset = task->length = 0;
            report_req_receipt_request(task, false);
        }
    } while (0);

    return result > 0 ? -1 * result : result;
}

static void receipt_thread_check_heartbeat(
        IdempotencyReceiptThreadContext *thread_ctx)
{
    IdempotencyClientChannel *channel;
    IdempotencyClientChannel *tmp;

    fc_list_for_each_entry_safe(channel, tmp, &thread_ctx->head, dlink) {
        if (g_current_time - channel->last_pkg_time <
                g_idempotency_client_cfg.channel_heartbeat_interval)
        {
            break;
        }

        if (sf_nio_task_is_idle(channel->task)) {
            channel->last_pkg_time = g_current_time;
            active_test_request(channel->task);
        }
    }
}

static void receipt_thread_close_idle_channel(
        IdempotencyReceiptThreadContext *thread_ctx)
{
    IdempotencyClientChannel *channel;
    IdempotencyClientChannel *tmp;

    fc_list_for_each_entry_safe(channel, tmp, &thread_ctx->head, dlink) {
        if (!sf_nio_task_is_idle(channel->task)) {
            continue;
        }

        if (g_current_time - channel->last_report_time >
                 g_idempotency_client_cfg.channel_max_idle_time)
        {
            logDebug("file: "__FILE__", line: %d, "
                    "close channel to server %s:%u because idle too long",
                    __LINE__, channel->task->server_ip, channel->task->port);
            close_channel_request(channel->task);
        }
    }
}

static int receipt_thread_loop_callback(struct nio_thread_data *thread_data)
{
    IdempotencyReceiptThreadContext *thread_ctx;
    thread_ctx = (IdempotencyReceiptThreadContext *)thread_data->arg;

    if (g_current_time - thread_ctx->last_check_times.heartbeat > 0) {
        thread_ctx->last_check_times.heartbeat = g_current_time;
        receipt_thread_check_heartbeat(thread_ctx);
    }

    if ((g_idempotency_client_cfg.channel_max_idle_time > 0) &&
            (g_current_time - thread_ctx->last_check_times.idle >
             g_idempotency_client_cfg.channel_max_idle_time))
    {
        thread_ctx->last_check_times.idle = g_current_time;
        receipt_thread_close_idle_channel(thread_ctx);
    }

    return 0;
}

static void *receipt_alloc_thread_extra_data(const int thread_index)
{
    IdempotencyReceiptThreadContext *ctx;

    ctx = receipt_thread_contexts + thread_index;
    FC_INIT_LIST_HEAD(&ctx->head);
    return ctx;
}

static int do_init()
{
    int bytes;

    bytes = sizeof(IdempotencyReceiptThreadContext) * SF_G_WORK_THREADS;
    receipt_thread_contexts = (IdempotencyReceiptThreadContext *)
        fc_malloc(bytes);
    if (receipt_thread_contexts == NULL) {
        return ENOMEM;
    }
    memset(receipt_thread_contexts, 0, bytes);

    return sf_service_init_ex2(&g_sf_context, "idemp-receipt",
            receipt_alloc_thread_extra_data, receipt_thread_loop_callback,
            NULL, sf_proto_set_body_length, receipt_deal_task,
            receipt_task_finish_cleanup, receipt_recv_timeout_callback,
            1000, sizeof(SFCommonProtoHeader), 0, receipt_init_task, NULL);
}

int receipt_handler_init()
{
    int result;

    if ((result=do_init()) != 0) {
        return result;
    }

    sf_enable_thread_notify(true);
    sf_set_remove_from_ready_list(false);
    fc_sleep_ms(100);

    return 0;
}

int receipt_handler_destroy()
{
    return 0;
}
