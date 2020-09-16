//server_handler.c

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
#include "../../sf_util.h"
#include "../../sf_global.h"
#include "../../sf_proto.h"
#include "server_channel.h"
#include "server_handler.h"

#define SF_TASK_BODY_LENGTH(task) \
    (task->length - sizeof(SFCommonProtoHeader))

int sf_server_deal_setup_channel(struct fast_task_info *task,
        int *task_type, IdempotencyChannel **channel,
        SFResponseInfo *response)
{
    int result;
    SFProtoSetupChannelReq *req;
    SFProtoSetupChannelResp *resp;
    uint32_t channel_id;
    int key;

    response->header.cmd = SF_SERVICE_PROTO_SETUP_CHANNEL_RESP;
    if ((result=sf_server_expect_body_length(response,
                    SF_TASK_BODY_LENGTH(task),
                    sizeof(SFProtoSetupChannelReq))) != 0)
    {
        return result;
    }

    req = (SFProtoSetupChannelReq *)(task->data + sizeof(SFCommonProtoHeader));
    channel_id = buff2int(req->channel_id);
    key = buff2int(req->key);
    if (*channel != NULL) {
        response->error.length = sprintf(response->error.message,
                "channel already setup, the channel id: %d", (*channel)->id);
        return EEXIST;
    }

    *channel = idempotency_channel_alloc(channel_id, key);
    if (*channel == NULL) {
        response->error.length = sprintf(response->error.message,
                "alloc channel fail, hint channel id: %d", channel_id);
        return ENOMEM;
    }

    *task_type = SF_SERVER_TASK_TYPE_CHANNEL_HOLDER;

    resp = (SFProtoSetupChannelResp *)(task->data +
            sizeof(SFCommonProtoHeader));
    int2buff((*channel)->id, resp->channel_id);
    int2buff((*channel)->key, resp->key);
    int2buff(task->size, resp->buffer_size);
    response->header.body_len = sizeof(SFProtoSetupChannelResp);
    return 0;
}

static int check_holder_channel(const int task_type,
        IdempotencyChannel *channel, SFResponseInfo *response)
{
    if (task_type != SF_SERVER_TASK_TYPE_CHANNEL_HOLDER) {
        response->error.length = sprintf(response->error.message,
                "unexpect task type: %d", task_type);
        return EINVAL;
    }

    if (channel == NULL) {
        response->error.length = sprintf(
                response->error.message,
                "channel not exist");
        return SF_RETRIABLE_ERROR_NO_CHANNEL;
    }

    return 0;
}

int sf_server_deal_close_channel(struct fast_task_info *task,
        int *task_type, IdempotencyChannel **channel,
        SFResponseInfo *response)
{
    int result;
    if ((result=check_holder_channel(*task_type, *channel, response)) != 0) {
        return result;
    }

    idempotency_channel_free(*channel);
    *channel = NULL;
    *task_type = SF_SERVER_TASK_TYPE_NONE;
    response->header.cmd = SF_SERVICE_PROTO_CLOSE_CHANNEL_RESP;
    return 0;
}

int sf_server_deal_report_req_receipt(struct fast_task_info *task,
        int *task_type, IdempotencyChannel **channel,
        SFResponseInfo *response)
{
    int result;
    int count;
    int success;
    int body_len;
    int calc_body_len;
    int64_t req_id;
    SFProtoReportReqReceiptHeader *body_header;
    SFProtoReportReqReceiptBody *body_part;
    SFProtoReportReqReceiptBody *body_end;

    if ((result=check_holder_channel(*task_type, *channel, response)) != 0) {
        return result;
    }

    body_len = SF_TASK_BODY_LENGTH(task);
    if ((result=sf_server_check_min_body_length(response, body_len,
                    sizeof(SFProtoReportReqReceiptHeader))) != 0)
    {
        return result;
    }

    body_header = (SFProtoReportReqReceiptHeader *)
    (task->data + sizeof(SFCommonProtoHeader));
    count = buff2int(body_header->count);
    calc_body_len = sizeof(SFProtoReportReqReceiptHeader) +
        sizeof(SFProtoReportReqReceiptBody) * count;
    if (body_len != calc_body_len) {
        response->error.length = sprintf(response->error.message,
                "body length: %d != calculated body length: %d",
                body_len, calc_body_len);
        return EINVAL;
    }

    success = 0;
    body_part = (SFProtoReportReqReceiptBody *)(body_header + 1);
    body_end = body_part + count;
    for (; body_part < body_end; body_part++) {
        req_id = buff2long(body_part->req_id);
        if (idempotency_channel_remove_request(*channel, req_id) == 0) {
            success++;
        }
    }

    logInfo("receipt count: %d, success: %d", count, success);

    response->header.cmd = SF_SERVICE_PROTO_REPORT_REQ_RECEIPT_RESP;
    return 0;
}
