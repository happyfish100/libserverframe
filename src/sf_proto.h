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

//sf_proto.h

#ifndef _SF_IDEMPOTENCY_PROTO_H
#define _SF_IDEMPOTENCY_PROTO_H

#include "fastcommon/fast_task_queue.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/connection_pool.h"
#include "fastcommon/sockopt.h"
#include "sf_define.h"
#include "sf_types.h"

#define SF_PROTO_ACK                    116

#define SF_PROTO_ACTIVE_TEST_REQ        117
#define SF_PROTO_ACTIVE_TEST_RESP       118

//for request idempotency
#define SF_SERVICE_PROTO_SETUP_CHANNEL_REQ        121
#define SF_SERVICE_PROTO_SETUP_CHANNEL_RESP       122
#define SF_SERVICE_PROTO_CLOSE_CHANNEL_REQ        123
#define SF_SERVICE_PROTO_CLOSE_CHANNEL_RESP       124
#define SF_SERVICE_PROTO_REPORT_REQ_RECEIPT_REQ   125
#define SF_SERVICE_PROTO_REPORT_REQ_RECEIPT_RESP  126

#define SF_PROTO_MAGIC_CHAR        '@'
#define SF_PROTO_SET_MAGIC(m)   \
    m[0] = m[1] = m[2] = m[3] = SF_PROTO_MAGIC_CHAR

#define SF_PROTO_CHECK_MAGIC(m) \
    (m[0] == SF_PROTO_MAGIC_CHAR && m[1] == SF_PROTO_MAGIC_CHAR && \
     m[2] == SF_PROTO_MAGIC_CHAR && m[3] == SF_PROTO_MAGIC_CHAR)

#define SF_PROTO_MAGIC_FORMAT "0x%02X%02X%02X%02X"
#define SF_PROTO_MAGIC_EXPECT_PARAMS \
    SF_PROTO_MAGIC_CHAR, SF_PROTO_MAGIC_CHAR, \
    SF_PROTO_MAGIC_CHAR, SF_PROTO_MAGIC_CHAR

#define SF_PROTO_MAGIC_PARAMS(m) \
    m[0], m[1], m[2], m[3]

#define SF_PROTO_SET_HEADER(header, _cmd, _body_len) \
    do {  \
        SF_PROTO_SET_MAGIC((header)->magic);   \
        (header)->cmd = _cmd;      \
        (header)->status[0] = (header)->status[1] = 0; \
        int2buff(_body_len, (header)->body_len); \
    } while (0)

#define SF_PROTO_SET_HEADER_EX(header, _cmd, _flags, _body_len) \
    do {  \
        SF_PROTO_SET_HEADER(header, _cmd, _body_len); \
        short2buff(_flags, (header)->flags); \
    } while (0)

#define SF_PROTO_SET_RESPONSE_HEADER(proto_header, resp_header) \
    do {  \
        (proto_header)->cmd = (resp_header).cmd;       \
        short2buff((resp_header).status, (proto_header)->status);  \
        int2buff((resp_header).body_len, (proto_header)->body_len);\
    } while (0)


typedef struct sf_common_proto_header {
    unsigned char magic[4]; //magic number
    char body_len[4];       //body length
    char status[2];         //status to store errno
    char flags[2];
    unsigned char cmd;      //the command code
    char padding[3];
} SFCommonProtoHeader;

typedef struct sf_proto_idempotency_additional_header {
    char req_id[8];
} SFProtoIdempotencyAdditionalHeader;

typedef struct sf_proto_setup_channel_req {
    char channel_id[4]; //for hint
    char key[4];        //for validate when channel_id > 0
} SFProtoSetupChannelReq;

typedef struct sf_proto_setup_channel_resp {
    char channel_id[4];
    char key[4];
    char buffer_size[4];
    char padding[4];
} SFProtoSetupChannelResp;

typedef struct sf_proto_report_req_receipt_header {
    char count[4];
    char padding[4];
} SFProtoReportReqReceiptHeader;

typedef struct sf_proto_report_req_receipt_body {
    char req_id[8];
} SFProtoReportReqReceiptBody;

#ifdef __cplusplus
extern "C" {
#endif

int sf_proto_set_body_length(struct fast_task_info *task);

const char *sf_get_cmd_caption(const int cmd);

static inline void sf_log_network_error_ex1(SFResponseInfo *response,
        const ConnectionInfo *conn, const int result,
        const int log_level, const char *file, const int line)
{
    if (response->error.length > 0) {
        log_it_ex(&g_log_context, log_level,
                "file: %s, line: %d, "
                "server %s:%u, %s", file, line,
                conn->ip_addr, conn->port,
                response->error.message);
    } else {
        log_it_ex(&g_log_context, log_level,
                "file: %s, line: %d, "
                "communicate with server %s:%u fail, "
                "errno: %d, error info: %s", file, line,
                conn->ip_addr, conn->port,
                result, STRERROR(result));
    }
}

#define sf_log_network_error_ex(response, conn, result, log_level) \
    sf_log_network_error_ex1(response, conn, result, \
            log_level, __FILE__, __LINE__)

#define sf_log_network_error(response, conn, result) \
    sf_log_network_error_ex1(response, conn, result, \
            LOG_ERR, __FILE__, __LINE__)


static inline int sf_server_expect_body_length(SFResponseInfo *response,
        const int body_length, const int expect_body_len)
{
    if (body_length != expect_body_len) {
        response->error.length = sprintf(
                response->error.message,
                "request body length: %d != %d",
                body_length, expect_body_len);
        return EINVAL;
    }

    return 0;
}

static inline int sf_server_check_min_body_length(SFResponseInfo *response,
        const int body_length, const int min_body_length)
{
    if (body_length < min_body_length) {
        response->error.length = sprintf(
                response->error.message,
                "request body length: %d < %d",
                body_length, min_body_length);
        return EINVAL;
    }

    return 0;
}

static inline int sf_server_check_max_body_length(SFResponseInfo *response,
        const int body_length, const int max_body_length)
{
    if (body_length > max_body_length) {
        response->error.length = sprintf(
                response->error.message,
                "request body length: %d > %d",
                body_length, max_body_length);
        return EINVAL;
    }

    return 0;
}

static inline int sf_server_check_body_length(
        SFResponseInfo *response, const int body_length,
        const int min_body_length, const int max_body_length)
{
    int result;
    if ((result=sf_server_check_min_body_length(response,
                    body_length, min_body_length)) != 0)
    {
        return result;
    }
    return sf_server_check_max_body_length(response,
            body_length, max_body_length);
}

int sf_check_response(ConnectionInfo *conn, SFResponseInfo *response,
        const int network_timeout, const unsigned char expect_cmd);

int sf_recv_response(ConnectionInfo *conn, SFResponseInfo *response,
        const int network_timeout, const unsigned char expect_cmd,
        char *recv_data, const int expect_body_len);

int sf_send_and_recv_response_header(ConnectionInfo *conn, char *data,
        const int len, SFResponseInfo *response, const int network_timeout);

static inline int sf_send_and_check_response_header(ConnectionInfo *conn,
        char *data, const int len, SFResponseInfo *response,
        const int network_timeout, const unsigned char expect_cmd)
{
    int result;

    if ((result=sf_send_and_recv_response_header(conn, data, len,
                    response, network_timeout)) != 0)
    {
        return result;
    }


    if ((result=sf_check_response(conn, response, network_timeout,
                    expect_cmd)) != 0)
    {
        return result;
    }

    return 0;
}

int sf_send_and_recv_response_ex1(ConnectionInfo *conn, char *send_data,
        const int send_len, SFResponseInfo *response,
        const int network_timeout, const unsigned char expect_cmd,
        char *recv_data, const int buff_size, int *body_len);

int sf_send_and_recv_response_ex(ConnectionInfo *conn, char *send_data,
        const int send_len, SFResponseInfo *response,
        const int network_timeout, const unsigned char expect_cmd,
        char *recv_data, const int *expect_body_lens,
        const int expect_body_len_count, int *body_len);

static inline int sf_send_and_recv_response(ConnectionInfo *conn,
        char *send_data, const int send_len, SFResponseInfo *response,
        const int network_timeout, const unsigned char expect_cmd,
        char *recv_data, const int expect_body_len)
{
    return sf_send_and_recv_response_ex(conn, send_data, send_len, response,
            network_timeout, expect_cmd, recv_data, &expect_body_len, 1, NULL);
}

static inline int sf_send_and_recv_none_body_response(ConnectionInfo *conn,
        char *send_data, const int send_len, SFResponseInfo *response,
        const int network_timeout, const unsigned char expect_cmd)
{
    char *recv_data = NULL;
    const int expect_body_len = 0;

    return sf_send_and_recv_response(conn, send_data, send_len, response,
        network_timeout, expect_cmd, recv_data, expect_body_len);
}

static inline void sf_proto_extract_header(SFCommonProtoHeader *header_proto,
        SFHeaderInfo *header_info)
{
    header_info->cmd = header_proto->cmd;
    header_info->body_len = buff2int(header_proto->body_len);
    header_info->flags = buff2short(header_proto->flags);
    header_info->status = buff2short(header_proto->status);
}

static inline int sf_active_test(ConnectionInfo *conn,
        SFResponseInfo *response, const int network_timeout)
{
    SFCommonProtoHeader proto_header;

    SF_PROTO_SET_HEADER(&proto_header, SF_PROTO_ACTIVE_TEST_REQ, 0);
    return sf_send_and_recv_none_body_response(conn, (char *)&proto_header,
            sizeof(proto_header), response, network_timeout,
            SF_PROTO_ACTIVE_TEST_RESP);
}

static inline int sf_proto_deal_active_test(struct fast_task_info *task,
        SFRequestInfo *request, SFResponseInfo *response)
{
    return sf_server_expect_body_length(response,
            request->header.body_len, 0);
}

int sf_proto_deal_ack(struct fast_task_info *task,
        SFRequestInfo *request, SFResponseInfo *response);

#define SF_CLIENT_RELEASE_CONNECTION(client_ctx, conn, result) \
    do {  \
        if (SF_FORCE_CLOSE_CONNECTION_ERROR(result)) {  \
            client_ctx->conn_manager.close_connection(client_ctx, conn);   \
        } else if (client_ctx->conn_manager.release_connection != NULL) {  \
            client_ctx->conn_manager.release_connection(client_ctx, conn); \
        } \
    } while (0)


#ifdef __cplusplus
}
#endif

#endif
