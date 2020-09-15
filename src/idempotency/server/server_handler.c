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

int service_deal_setup_channel(struct fast_task_info *task,
        int *task_type, IdempotencyChannel **channel,
        SFResponseInfo *response)
{
    int result;
    FSProtoSetupChannelReq *req;
    FSProtoSetupChannelResp *resp;
    uint32_t channel_id;
    int key;

    response->header.cmd = FS_SERVICE_PROTO_SETUP_CHANNEL_RESP;
    if ((result=sf_server_expect_body_length(response,
                    SF_TASK_BODY_LENGTH(task),
                    sizeof(FSProtoSetupChannelReq))) != 0)
    {
        return result;
    }

    req = (FSProtoSetupChannelReq *)(task->data + sizeof(SFCommonProtoHeader));
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

    *task_type = FS_SERVER_TASK_TYPE_CHANNEL_HOLDER;

    resp = (FSProtoSetupChannelResp *)(task->data +
            sizeof(SFCommonProtoHeader));
    int2buff((*channel)->id, resp->channel_id);
    int2buff((*channel)->key, resp->key);
    response->header.body_len = sizeof(FSProtoSetupChannelResp);
    //TASK_ARG->context.response_done = true;
    return 0;
}

/*
static int check_holder_channel(struct fast_task_info *task)
{   
    if (SERVER_TASK_TYPE != FS_SERVER_TASK_TYPE_CHANNEL_HOLDER) {
        RESPONSE.error.length = sprintf(RESPONSE.error.message,
                "unexpect task type: %d", SERVER_TASK_TYPE);
        return EINVAL;
    }

    if (*channel == NULL) {
        RESPONSE.error.length = sprintf(
                RESPONSE.error.message,
                "channel not exist");
        return SF_RETRIABLE_ERROR_NO_CHANNEL;
    }

    return 0;
}

int service_deal_close_channel(struct fast_task_info *task)
{
    int result;
    if ((result=check_holder_channel(task)) != 0) {
        return result;
    }

    RESPONSE.header.cmd = FS_SERVICE_PROTO_CLOSE_CHANNEL_RESP;
    idempotency_channel_free(*channel);
    *channel = NULL;
    *task_type = FS_SERVER_TASK_TYPE_NONE;
    return 0;
}

int service_deal_report_req_receipt(struct fast_task_info *task)
{
    int result;
    int count;
    int success;
    int body_len;
    int calc_body_len;
    int64_t req_id;
    FSProtoReportReqReceiptHeader *body_header;
    FSProtoReportReqReceiptBody *body_part;
    FSProtoReportReqReceiptBody *body_end;

    if ((result=check_holder_channel(task)) != 0) {
        return result;
    }

    body_len = SF_TASK_BODY_LENGTH(task);
    if ((result=sf_server_check_min_body_length(response, body_len,
                    sizeof(FSProtoReportReqReceiptHeader))) != 0)
    {
        return result;
    }

    body_header = (FSProtoReportReqReceiptHeader *)
    (task->data + sizeof(SFCommonProtoHeader));
    count = buff2int(body_header->count);
    calc_body_len = sizeof(FSProtoReportReqReceiptHeader) +
        sizeof(FSProtoReportReqReceiptBody) * count;
    if (body_len != calc_body_len) {
        RESPONSE.error.length = sprintf(RESPONSE.error.message,
                "body length: %d != calculated body length: %d",
                body_len, calc_body_len);
        return EINVAL;
    }

    success = 0;
    body_part = (FSProtoReportReqReceiptBody *)(body_header + 1);
    body_end = body_part + count;
    for (; body_part < body_end; body_part++) {
        req_id = buff2long(body_part->req_id);
        if (idempotency_channel_remove_request(*channel, req_id) == 0) {
            success++;
        }
    }

    logInfo("receipt count: %d, success: %d", count, success);

    RESPONSE.header.cmd = FS_SERVICE_PROTO_REPORT_REQ_RECEIPT_RESP;
    return 0;
}

*/
