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
#include "sf_util.h"

//for connection manager
#define SF_SERVICE_PROTO_GET_GROUP_SERVERS_REQ    111
#define SF_SERVICE_PROTO_GET_GROUP_SERVERS_RESP   112
#define SF_SERVICE_PROTO_GET_LEADER_REQ           113
#define SF_SERVICE_PROTO_GET_LEADER_RESP          114

#define SF_PROTO_ACK                    116

#define SF_PROTO_ACTIVE_TEST_REQ        117
#define SF_PROTO_ACTIVE_TEST_RESP       118

//for request idempotency
#define SF_SERVICE_PROTO_SETUP_CHANNEL_REQ        119
#define SF_SERVICE_PROTO_SETUP_CHANNEL_RESP       120
#define SF_SERVICE_PROTO_CLOSE_CHANNEL_REQ        121
#define SF_SERVICE_PROTO_CLOSE_CHANNEL_RESP       122
#define SF_SERVICE_PROTO_REBIND_CHANNEL_REQ       123
#define SF_SERVICE_PROTO_REBIND_CHANNEL_RESP      124
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

#define SF_PROTO_RESP_BODY(task)  \
    (task->data + sizeof(SFCommonProtoHeader))

#define SF_PROTO_UPDATE_EXTRA_BODY_SIZE \
    sizeof(SFProtoIdempotencyAdditionalHeader) + FCFS_AUTH_SESSION_ID_LEN

#define SF_PROTO_QUERY_EXTRA_BODY_SIZE  FCFS_AUTH_SESSION_ID_LEN

#define SF_PROTO_CLIENT_SET_REQ(client_ctx, out_buff, \
        header, req, the_req_id, out_bytes) \
    do {   \
        char *the_req_start;  \
        header = (SFCommonProtoHeader *)out_buff; \
        the_req_start = (char *)(header + 1);     \
        out_bytes = sizeof(SFCommonProtoHeader) + sizeof(*req); \
        if (client_ctx->auth.enabled) { \
            out_bytes += FCFS_AUTH_SESSION_ID_LEN;   \
            memcpy(the_req_start, client_ctx->auth.ctx-> \
                    session.id, FCFS_AUTH_SESSION_ID_LEN);  \
            the_req_start += FCFS_AUTH_SESSION_ID_LEN;   \
        }  \
        if (the_req_id > 0) {  \
            long2buff(the_req_id, ((SFProtoIdempotencyAdditionalHeader *)\
                        the_req_start)->req_id);  \
            out_bytes += sizeof(SFProtoIdempotencyAdditionalHeader); \
            req = (typeof(req))(the_req_start +   \
                    sizeof(SFProtoIdempotencyAdditionalHeader));     \
        } else {  \
            req = (typeof(req))the_req_start;  \
        }  \
    } while (0)


typedef struct sf_common_proto_header {
    unsigned char magic[4]; //magic number
    char body_len[4];       //body length
    char status[2];         //status to store errno
    char flags[2];
    unsigned char cmd;      //the command code
    char padding[3];
} SFCommonProtoHeader;

typedef struct sf_proto_limit_info {
    char offset[4];
    char count[4];
} SFProtoLimitInfo;

typedef struct sf_proto_get_group_servers_req {
    char group_id[4];
    char padding[4];
} SFProtoGetGroupServersReq;

typedef struct sf_proto_get_group_servers_resp_body_header {
    char count[4];
    char padding[4];
} SFProtoGetGroupServersRespBodyHeader;

typedef struct sf_proto_get_group_servers_resp_body_part {
    char server_id[4];
    char is_master;
    char is_active;
    char padding[2];
} SFProtoGetGroupServersRespBodyPart;

typedef struct sf_proto_get_server_resp {
    char ip_addr[IP_ADDRESS_SIZE];
    char server_id[4];
    char port[2];
    char padding[2];
} SFProtoGetServerResp;

typedef struct sf_proto_empty_body_req {
    char nothing[0];
} SFProtoEmptyBodyReq;

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

typedef struct sf_proto_rebind_channel_req {
    char channel_id[4];
    char key[4];
} SFProtoRebindChannelReq;

typedef struct sf_proto_report_req_receipt_header {
    char count[4];
    char padding[4];
} SFProtoReportReqReceiptHeader;

typedef struct sf_proto_report_req_receipt_body {
    char req_id[8];
} SFProtoReportReqReceiptBody;

typedef struct sf_group_server_info {
    int id;
    bool is_leader;
    bool is_master;
    bool is_active;
    char padding[1];
} SFGroupServerInfo;

typedef struct sf_group_server_array {
    SFGroupServerInfo *servers;
    int alloc;
    int count;
} SFGroupServerArray;

typedef struct sf_client_server_entry {
    int server_id;
    ConnectionInfo conn;
} SFClientServerEntry;

typedef const char *(*sf_get_cmd_caption_func)(const int cmd);
typedef int (*sf_get_cmd_log_level_func)(const int cmd);

typedef struct {
    int alloc_size;
    int fixed_size;
    char *fixed;
    char *buff;
} SFProtoRecvBuffer;

typedef struct {
    char fixed[64 * 1024];
    SFProtoRecvBuffer buffer;
} SFProtoRBufferFixedWrapper;

typedef struct {
    sf_get_cmd_caption_func get_cmd_caption;
    sf_get_cmd_log_level_func get_cmd_log_level;
} SFCommandCallbacks;

typedef struct {
    SFSlowLogContext *slow_log;
    SFCommandCallbacks callbacks;
} SFHandlerContext;

#ifdef __cplusplus
extern "C" {
#endif

void sf_proto_set_handler_context(const SFHandlerContext *ctx);

int sf_proto_set_body_length(struct fast_task_info *task);

const char *sf_get_cmd_caption(const int cmd);

int sf_proto_deal_task_done(struct fast_task_info *task,
        SFCommonTaskContext *ctx);

static inline void sf_proto_init_task_context(struct fast_task_info *task,
        SFCommonTaskContext *ctx)
{
    ctx->req_start_time = get_current_time_us();
    ctx->response.header.cmd = SF_PROTO_ACK;
    ctx->response.header.body_len = 0;
    ctx->response.header.status = 0;
    ctx->response.error.length = 0;
    ctx->response.error.message[0] = '\0';
    ctx->log_level = LOG_ERR;
    ctx->response_done = false;
    ctx->need_response = true;

    ctx->request.header.cmd = ((SFCommonProtoHeader *)task->data)->cmd;
    ctx->request.header.body_len = task->length - sizeof(SFCommonProtoHeader);
    ctx->request.header.status = buff2short(((SFCommonProtoHeader *)
                task->data)->status);
    ctx->request.body = task->data + sizeof(SFCommonProtoHeader);
}

static inline void sf_log_network_error_ex1(SFResponseInfo *response,
        const ConnectionInfo *conn, const int result,
        const int log_level, const char *file, const int line)
{
    if (response->error.length > 0) {
        log_it_ex(&g_log_context, log_level,
                "file: %s, line: %d, "
                "server %s:%u response message: %s",
                file, line, conn->ip_addr, conn->port,
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

#define sf_log_network_error_for_update(response, conn, result)  \
        sf_log_network_error_ex(response, conn, result,         \
                (result == SF_RETRIABLE_ERROR_CHANNEL_INVALID) ? \
                LOG_DEBUG : LOG_ERR)

#define sf_log_network_error_for_delete(response, \
        conn, result, enoent_log_level)  \
        sf_log_network_error_ex(response, conn, result,          \
                (result == SF_RETRIABLE_ERROR_CHANNEL_INVALID) ? \
                LOG_DEBUG : ((result == ENOENT || result == ENODATA) ? \
                    enoent_log_level : LOG_ERR))

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

#define server_expect_body_length(expect_body_len) \
    sf_server_expect_body_length(&RESPONSE, REQUEST.header.body_len, \
            expect_body_len)

#define server_check_min_body_length(min_body_length) \
    sf_server_check_min_body_length(&RESPONSE, REQUEST.header.body_len, \
            min_body_length)

#define server_check_max_body_length(max_body_length) \
    sf_server_check_max_body_length(&RESPONSE, REQUEST.header.body_len, \
            max_body_length)

#define server_check_body_length(min_body_length, max_body_length) \
    sf_server_check_body_length(&RESPONSE, REQUEST.header.body_len, \
            min_body_length, max_body_length)


int sf_check_response(ConnectionInfo *conn, SFResponseInfo *response,
        const int network_timeout, const unsigned char expect_cmd);

int sf_recv_response(ConnectionInfo *conn, SFResponseInfo *response,
        const int network_timeout, const unsigned char expect_cmd,
        char *recv_data, const int expect_body_len);

int sf_recv_vary_response(ConnectionInfo *conn, SFResponseInfo *response,
        const int network_timeout, const unsigned char expect_cmd,
        SFProtoRecvBuffer *buffer, const int min_body_len);

static inline void sf_init_recv_buffer_by_wrapper(
        SFProtoRBufferFixedWrapper *wrapper)
{
    wrapper->buffer.fixed_size = sizeof(wrapper->fixed);
    wrapper->buffer.alloc_size = sizeof(wrapper->fixed);
    wrapper->buffer.fixed = wrapper->fixed;
    wrapper->buffer.buff = wrapper->fixed;
}

static inline int sf_init_recv_buffer(SFProtoRecvBuffer *buffer,
        const int init_size)
{
    buffer->alloc_size = init_size;
    buffer->fixed_size = 0;
    buffer->fixed = NULL;
    buffer->buff = (char *)fc_malloc(init_size);
    return buffer->buff != NULL ? 0 : ENOMEM;
}

static inline void sf_free_recv_buffer(SFProtoRecvBuffer *buffer)
{
    if (buffer->buff != buffer->fixed) {
        if (buffer->buff != NULL) {
            free(buffer->buff);
        }
        buffer->alloc_size = buffer->fixed_size;
        buffer->buff = buffer->fixed;
    }
}

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

int sf_send_and_recv_vary_response(ConnectionInfo *conn,
        char *send_data, const int send_len, SFResponseInfo *response,
        const int network_timeout, const unsigned char expect_cmd,
        SFProtoRecvBuffer *buffer, const int min_body_len);

static inline void sf_proto_extract_header(const SFCommonProtoHeader
        *header_proto, SFHeaderInfo *header_info)
{
    header_info->cmd = header_proto->cmd;
    header_info->body_len = buff2int(header_proto->body_len);
    header_info->flags = buff2short(header_proto->flags);
    header_info->status = buff2short(header_proto->status);
    if (header_info->status > 255) {
        header_info->status = sf_localize_errno(header_info->status);
    }
}

static inline void sf_proto_pack_limit(const SFListLimitInfo
        *limit_info, SFProtoLimitInfo *limit_proto)
{
    int2buff(limit_info->offset, limit_proto->offset);
    int2buff(limit_info->count, limit_proto->count);
}

static inline void sf_proto_extract_limit(const SFProtoLimitInfo
        *limit_proto, SFListLimitInfo *limit_info)
{
    limit_info->offset = buff2int(limit_proto->offset);
    limit_info->count = buff2int(limit_proto->count);
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

int sf_proto_rebind_idempotency_channel(ConnectionInfo *conn,
        const uint32_t channel_id, const int key, const int network_timeout);

int sf_proto_get_group_servers(ConnectionInfo *conn,
        const int network_timeout, const int group_id,
        SFGroupServerArray *sarray);

int sf_proto_get_leader(ConnectionInfo *conn,
        const int network_timeout,
        SFClientServerEntry *leader);


#define SF_CLIENT_RELEASE_CONNECTION(cm, conn, result) \
    do { \
        if (SF_FORCE_CLOSE_CONNECTION_ERROR(result)) {  \
            (cm)->ops.close_connection(cm, conn);   \
        } else if ((cm)->ops.release_connection != NULL) {  \
            (cm)->ops.release_connection(cm, conn); \
        } \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif
