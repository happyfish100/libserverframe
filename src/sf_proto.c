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


#include <errno.h>
#include "fastcommon/shared_func.h"
#include "sf_util.h"
#include "sf_nio.h"
#include "sf_proto.h"

static SFHandlerContext sf_handler_ctx = {NULL, {NULL, NULL}};
static int64_t log_slower_than_us = 0;

#define GET_CMD_CAPTION(cmd)    sf_handler_ctx.callbacks.get_cmd_caption(cmd)
#define GET_CMD_LOG_LEVEL(cmd)  sf_handler_ctx.callbacks.get_cmd_log_level(cmd)

int sf_proto_set_body_length(struct fast_task_info *task)
{
    SFCommonProtoHeader *header;

    header = (SFCommonProtoHeader *)task->data;
    if (!SF_PROTO_CHECK_MAGIC(header->magic)) {
        logError("file: "__FILE__", line: %d, "
                "peer %s:%u, magic "SF_PROTO_MAGIC_FORMAT
                " is invalid, expect: "SF_PROTO_MAGIC_FORMAT,
                __LINE__, task->client_ip, task->port,
                SF_PROTO_MAGIC_PARAMS(header->magic),
                SF_PROTO_MAGIC_EXPECT_PARAMS);
        return EINVAL;
    }

    task->length = buff2int(header->body_len); //set body length
    return 0;
}

int sf_check_response(ConnectionInfo *conn, SFResponseInfo *response,
        const int network_timeout, const unsigned char expect_cmd)
{
    int result;

    if (response->header.status == 0) {
        if (response->header.cmd != expect_cmd) {
            response->error.length = sprintf(
                    response->error.message,
                    "response cmd: %d != expect: %d",
                    response->header.cmd, expect_cmd);
            return EINVAL;
        }

        return 0;
    }

    if (response->header.body_len > 0) {
        int recv_bytes;
        if (response->header.body_len >= sizeof(response->error.message)) {
            response->error.length = sizeof(response->error.message) - 1;
        } else {
            response->error.length = response->header.body_len;
        }

        if ((result=tcprecvdata_nb_ex(conn->sock, response->error.message,
                response->error.length, network_timeout, &recv_bytes)) == 0)
        {
            response->error.message[response->error.length] = '\0';
        } else {
            response->error.length = snprintf(response->error.message,
                    sizeof(response->error.message),
                    "recv error message fail, "
                    "recv bytes: %d, expect message length: %d, "
                    "errno: %d, error info: %s", recv_bytes,
                    response->error.length, result, STRERROR(result));
        }
    } else {
        response->error.length = snprintf(response->error.message,
                sizeof(response->error.message), "response status %d, "
                "error info: %s", response->header.status,
                sf_strerror(response->header.status));
    }

    return response->header.status;
}

static inline int sf_recv_response_header(ConnectionInfo *conn,
        SFResponseInfo *response, const int network_timeout)
{
    int result;
    SFCommonProtoHeader header_proto;

    if ((result=tcprecvdata_nb(conn->sock, &header_proto,
            sizeof(SFCommonProtoHeader), network_timeout)) != 0)
    {
        response->error.length = snprintf(response->error.message,
                sizeof(response->error.message),
                "recv data fail, errno: %d, error info: %s",
                result, STRERROR(result));
        return result;
    }

    if (!SF_PROTO_CHECK_MAGIC(header_proto.magic)) {
        response->error.length = snprintf(response->error.message,
                sizeof(response->error.message),
                "magic "SF_PROTO_MAGIC_FORMAT" is invalid, "
                "expect: "SF_PROTO_MAGIC_FORMAT,
                SF_PROTO_MAGIC_PARAMS(header_proto.magic),
                SF_PROTO_MAGIC_EXPECT_PARAMS);
        return EINVAL;
    }

    sf_proto_extract_header(&header_proto, &response->header);
    return 0;
}

int sf_send_and_recv_response_header(ConnectionInfo *conn, char *data,
        const int len, SFResponseInfo *response, const int network_timeout)
{
    int result;

    if ((result=tcpsenddata_nb(conn->sock, data, len, network_timeout)) != 0) {
        response->error.length = snprintf(response->error.message,
                sizeof(response->error.message),
                "send data fail, errno: %d, error info: %s",
                result, STRERROR(result));
        return result;
    }

    return sf_recv_response_header(conn, response, network_timeout);
}

int sf_send_and_recv_response_ex(ConnectionInfo *conn, char *send_data,
        const int send_len, SFResponseInfo *response,
        const int network_timeout, const unsigned char expect_cmd,
        char *recv_data, const int *expect_body_lens,
        const int expect_body_len_count, int *body_len)
{
    int result;
    int recv_bytes;
    int i;

    if ((result=sf_send_and_check_response_header(conn, send_data, send_len,
                    response, network_timeout, expect_cmd)) != 0)
    {
        return result;
    }

    if (body_len != NULL) {
        *body_len = response->header.body_len;
    }

    if (response->header.body_len != expect_body_lens[0]) {
        for (i=1; i<expect_body_len_count; i++) {
            if (response->header.body_len == expect_body_lens[i]) {
                break;
            }
        }

        if (i == expect_body_len_count) {
            if (expect_body_len_count == 1) {
                response->error.length = sprintf(
                        response->error.message,
                        "response body length: %d != %d",
                        response->header.body_len,
                        expect_body_lens[0]);
            } else {
                response->error.length = sprintf(
                        response->error.message,
                        "response body length: %d not in [%d",
                        response->header.body_len,
                        expect_body_lens[0]);
                for (i=1; i<expect_body_len_count; i++) {
                    response->error.length += sprintf(
                            response->error.message +
                            response->error.length,
                            ", %d", expect_body_lens[i]);
                }
                *(response->error.message + response->error.length++) = ']';
                *(response->error.message + response->error.length) = '\0';
            }
            return EINVAL;
        }
    }
    if (response->header.body_len == 0) {
        return 0;
    }

    if ((result=tcprecvdata_nb_ex(conn->sock, recv_data, response->
                    header.body_len, network_timeout, &recv_bytes)) != 0)
    {
        response->error.length = snprintf(response->error.message,
                sizeof(response->error.message),
                "recv body fail, recv bytes: %d, expect body length: %d, "
                "errno: %d, error info: %s", recv_bytes,
                response->header.body_len,
                result, STRERROR(result));
    }
    return result;
}

int sf_send_and_recv_response_ex1(ConnectionInfo *conn, char *send_data,
        const int send_len, SFResponseInfo *response,
        const int network_timeout, const unsigned char expect_cmd,
        char *recv_data, const int buff_size, int *body_len)
{
    int result;

    if ((result=sf_send_and_check_response_header(conn, send_data, send_len,
                    response, network_timeout, expect_cmd)) != 0)
    {
        *body_len = 0;
        return result;
    }

    if (response->header.body_len == 0) {
        *body_len = 0;
        return 0;
    }

    if (response->header.body_len > buff_size) {
        response->error.length = sprintf(response->error.message,
                "response body length: %d exceeds buffer size: %d",
                response->header.body_len, buff_size);
        *body_len = 0;
        return EOVERFLOW;
    }

    if ((result=tcprecvdata_nb_ex(conn->sock, recv_data, response->
                    header.body_len, network_timeout, body_len)) != 0)
    {
        response->error.length = snprintf(response->error.message,
                sizeof(response->error.message),
                "recv body fail, recv bytes: %d, expect body length: %d, "
                "errno: %d, error info: %s", *body_len, response->
                header.body_len, result, STRERROR(result));
    }
    return result;
}

int sf_recv_response(ConnectionInfo *conn, SFResponseInfo *response,
        const int network_timeout, const unsigned char expect_cmd,
        char *recv_data, const int expect_body_len)
{
    int result;
    int recv_bytes;

    if ((result=sf_recv_response_header(conn, response,
                    network_timeout)) != 0)
    {
        return result;
    }
    if ((result=sf_check_response(conn, response, network_timeout,
                    expect_cmd)) != 0)
    {
        return result;
    }

    if (response->header.body_len != expect_body_len) {
        response->error.length = sprintf(response->error.message,
                "response body length: %d != %d",
                response->header.body_len,
                expect_body_len);
        return EINVAL;
    }
    if (expect_body_len == 0) {
        return 0;
    }

    if ((result=tcprecvdata_nb_ex(conn->sock, recv_data, expect_body_len,
                    network_timeout, &recv_bytes)) != 0)
    {
        response->error.length = snprintf(response->error.message,
                sizeof(response->error.message),
                "recv body fail, recv bytes: %d, expect body length: %d, "
                "errno: %d, error info: %s", recv_bytes,
                response->header.body_len,
                result, STRERROR(result));
    }

    return result;
}

int sf_recv_vary_response(ConnectionInfo *conn, SFResponseInfo *response,
        const int network_timeout, const unsigned char expect_cmd,
        SFProtoRecvBuffer *buffer, const int min_body_len)
{
    int result;
    int recv_bytes;

    if ((result=sf_recv_response_header(conn, response,
                    network_timeout)) != 0)
    {
        return result;
    }
    if ((result=sf_check_response(conn, response, network_timeout,
                    expect_cmd)) != 0)
    {
        return result;
    }

    if (response->header.body_len < min_body_len) {
        response->error.length = sprintf(response->error.message,
                "response body length: %d < %d",
                response->header.body_len, min_body_len);
        return EINVAL;
    }

    if (response->header.body_len <= buffer->alloc_size) {
        if (response->header.body_len == 0) {
            return 0;
        }
    } else {
        int alloc_size;
        char *buff;

        if (buffer->alloc_size > 0) {
            alloc_size = 2 * buffer->alloc_size;
        } else {
            alloc_size = 64 * 1024;
        }
        while (alloc_size < response->header.body_len) {
            alloc_size *= 2;
        }

        buff = (char *)fc_malloc(alloc_size);
        if (buff == NULL) {
            return ENOMEM;
        }
        if (buffer->buff != buffer->fixed && buffer->buff != NULL) {
            free(buffer->buff);
        }

        buffer->buff = buff;
        buffer->alloc_size = alloc_size;
    }

    if ((result=tcprecvdata_nb_ex(conn->sock, buffer->buff, response->
                    header.body_len, network_timeout, &recv_bytes)) != 0)
    {
        response->error.length = snprintf(response->error.message,
                sizeof(response->error.message),
                "recv body fail, recv bytes: %d, expect body length: %d, "
                "errno: %d, error info: %s", recv_bytes,
                response->header.body_len,
                result, STRERROR(result));
    }

    return result;
}

int sf_send_and_recv_vary_response(ConnectionInfo *conn,
        char *send_data, const int send_len, SFResponseInfo *response,
        const int network_timeout, const unsigned char expect_cmd,
        SFProtoRecvBuffer *buffer, const int min_body_len)
{
    int result;

    if ((result=tcpsenddata_nb(conn->sock, send_data,
                    send_len, network_timeout)) != 0)
    {
        response->error.length = snprintf(response->error.message,
                sizeof(response->error.message),
                "send data fail, errno: %d, error info: %s",
                result, STRERROR(result));
        return result;
    }

    return sf_recv_vary_response(conn, response, network_timeout,
            expect_cmd, buffer, min_body_len);
}

const char *sf_get_cmd_caption(const int cmd)
{
    switch (cmd) {
        case SF_PROTO_ACK:
            return "ACK";
        case SF_PROTO_ACTIVE_TEST_REQ:
            return "ACTIVE_TEST_REQ";
        case SF_PROTO_ACTIVE_TEST_RESP:
            return "ACTIVE_TEST_RESP";
        case SF_SERVICE_PROTO_SETUP_CHANNEL_REQ:
            return "SETUP_CHANNEL_REQ";
        case SF_SERVICE_PROTO_SETUP_CHANNEL_RESP:
            return "SETUP_CHANNEL_RESP";
        case SF_SERVICE_PROTO_CLOSE_CHANNEL_REQ:
            return "CLOSE_CHANNEL_REQ";
        case SF_SERVICE_PROTO_CLOSE_CHANNEL_RESP:
            return "CLOSE_CHANNEL_RESP";
        case SF_SERVICE_PROTO_REBIND_CHANNEL_REQ:
            return "REBIND_CHANNEL_REQ";
        case SF_SERVICE_PROTO_REBIND_CHANNEL_RESP:
            return "REBIND_CHANNEL_RESP";
        case SF_SERVICE_PROTO_REPORT_REQ_RECEIPT_REQ:
            return "REPORT_REQ_RECEIPT_REQ";
        case SF_SERVICE_PROTO_REPORT_REQ_RECEIPT_RESP:
            return "REPORT_REQ_RECEIPT_RESP";
        case SF_SERVICE_PROTO_GET_GROUP_SERVERS_REQ:
            return "GET_GROUP_SERVERS_REQ";
        case SF_SERVICE_PROTO_GET_GROUP_SERVERS_RESP:
            return "GET_GROUP_SERVERS_RESP";
        case SF_SERVICE_PROTO_GET_LEADER_REQ:
            return "GET_LEADER_REQ";
        case SF_SERVICE_PROTO_GET_LEADER_RESP:
            return "GET_LEADER_RESP";
        default:
            return "UNKOWN";
    }
}

int sf_proto_deal_ack(struct fast_task_info *task,
        SFRequestInfo *request, SFResponseInfo *response)
{
    if (request->header.status != 0) {
        if (request->header.body_len > 0) {
            int remain_size;
            int len;

            response->error.length = sprintf(response->error.message,
                    "message from peer %s:%u => ",
                    task->client_ip, task->port);
            remain_size = sizeof(response->error.message) -
                response->error.length;
            if (request->header.body_len >= remain_size) {
                len = remain_size - 1;
            } else {
                len = request->header.body_len;
            }

            memcpy(response->error.message + response->error.length,
                    request->body, len);
            response->error.length += len;
            *(response->error.message + response->error.length) = '\0';
        }

        return request->header.status;
    }

    if (request->header.body_len > 0) {
        response->error.length = sprintf(response->error.message,
                "ACK body length: %d != 0", request->header.body_len);
        return -EINVAL;
    }

    return 0;
}

int sf_proto_rebind_idempotency_channel(ConnectionInfo *conn,
        const uint32_t channel_id, const int key, const int network_timeout)
{
    char out_buff[sizeof(SFCommonProtoHeader) +
        sizeof(SFProtoRebindChannelReq)];
    SFCommonProtoHeader *header;
    SFProtoRebindChannelReq *req;
    SFResponseInfo response;
    int result;

    header = (SFCommonProtoHeader *)out_buff;
    req = (SFProtoRebindChannelReq *)(header + 1);
    int2buff(channel_id, req->channel_id);
    int2buff(key, req->key);
    SF_PROTO_SET_HEADER(header, SF_SERVICE_PROTO_REBIND_CHANNEL_REQ,
            sizeof(SFProtoRebindChannelReq));
    response.error.length = 0;
    if ((result=sf_send_and_recv_none_body_response(conn, out_buff,
                    sizeof(out_buff), &response, network_timeout,
                    SF_SERVICE_PROTO_REBIND_CHANNEL_RESP)) != 0)
    {
        sf_log_network_error(&response, conn, result);
    }

    return result;
}

int sf_proto_get_group_servers(ConnectionInfo *conn,
        const int network_timeout, const int group_id,
        SFGroupServerArray *sarray)
{
    char out_buff[sizeof(SFCommonProtoHeader) +
        sizeof(SFProtoGetGroupServersReq)];
    char in_buff[1024];
    SFCommonProtoHeader *header;
    SFProtoGetGroupServersReq *req;
    SFProtoGetGroupServersRespBodyHeader *body_header;
    SFProtoGetGroupServersRespBodyPart *body_part;
    SFGroupServerInfo *server;
    SFGroupServerInfo *end;
    SFResponseInfo response;
    int result;
    int body_len;
    int count;

    header = (SFCommonProtoHeader *)out_buff;
    req = (SFProtoGetGroupServersReq *)(header + 1);
    int2buff(group_id, req->group_id);
    SF_PROTO_SET_HEADER(header, SF_SERVICE_PROTO_GET_GROUP_SERVERS_REQ,
            sizeof(SFProtoGetGroupServersReq));
    response.error.length = 0;
    if ((result=sf_send_and_recv_response_ex1(conn, out_buff,
                    sizeof(out_buff), &response, network_timeout,
                    SF_SERVICE_PROTO_GET_GROUP_SERVERS_RESP, in_buff,
                    sizeof(in_buff), &body_len)) != 0)
    {
        sf_log_network_error(&response, conn, result);
        return result;
    }

    if (body_len < sizeof(SFProtoGetGroupServersRespBodyHeader)) {
        logError("file: "__FILE__", line: %d, "
                "server %s:%d response body length: %d < %d",
                __LINE__, conn->ip_addr, conn->port, body_len,
                (int)sizeof(SFProtoGetGroupServersRespBodyHeader));
        return EINVAL;
    }

    body_header = (SFProtoGetGroupServersRespBodyHeader *)in_buff;
    count = buff2int(body_header->count);
    if (count <= 0) {
        logError("file: "__FILE__", line: %d, "
                "server %s:%d response server count: %d <= 0",
                __LINE__, conn->ip_addr, conn->port, count);
        return EINVAL;
    }
    if (count > sarray->alloc) {
        logError("file: "__FILE__", line: %d, "
                "server %s:%d response server count: %d is too large, "
                "exceeds %d", __LINE__, conn->ip_addr, conn->port,
                count, sarray->alloc);
        return EOVERFLOW;
    }
    sarray->count = count;

    body_part = (SFProtoGetGroupServersRespBodyPart *)(body_header + 1);
    end = sarray->servers + sarray->count;
    for (server=sarray->servers; server<end; server++, body_part++) {
        server->id = buff2int(body_part->server_id);
        server->is_master = body_part->is_master;
        server->is_active = body_part->is_active;
    }

    return 0;
}

int sf_proto_get_leader(ConnectionInfo *conn,
        const int network_timeout,
        SFClientServerEntry *leader)
{
    int result;
    SFCommonProtoHeader *header;
    SFResponseInfo response;
    SFProtoGetServerResp server_resp;
    char out_buff[sizeof(SFCommonProtoHeader)];

    header = (SFCommonProtoHeader *)out_buff;
    SF_PROTO_SET_HEADER(header, SF_SERVICE_PROTO_GET_LEADER_REQ,
            sizeof(out_buff) - sizeof(SFCommonProtoHeader));
    if ((result=sf_send_and_recv_response(conn, out_buff,
                    sizeof(out_buff), &response, network_timeout,
                    SF_SERVICE_PROTO_GET_LEADER_RESP, (char *)&server_resp,
                    sizeof(SFProtoGetServerResp))) != 0)
    {
        sf_log_network_error(&response, conn, result);
    } else {
        leader->server_id = buff2int(server_resp.server_id);
        memcpy(leader->conn.ip_addr, server_resp.ip_addr, IP_ADDRESS_SIZE);
        *(leader->conn.ip_addr + IP_ADDRESS_SIZE - 1) = '\0';
        leader->conn.port = buff2short(server_resp.port);
    }

    return result;
}

void sf_proto_set_handler_context(const SFHandlerContext *ctx)
{
    sf_handler_ctx = *ctx;
    log_slower_than_us = ctx->slow_log->cfg.log_slower_than_ms * 1000;
}

int sf_proto_deal_task_done(struct fast_task_info *task,
        SFCommonTaskContext *ctx)
{
    SFCommonProtoHeader *proto_header;
    int status;
    int r;
    int64_t time_used;
    int log_level;
    char time_buff[32];

    if (ctx->log_level != LOG_NOTHING && ctx->response.error.length > 0) {
        log_it_ex(&g_log_context, ctx->log_level,
                "file: "__FILE__", line: %d, "
                "peer %s:%u, cmd: %d (%s), req body length: %d, "
                "resp status: %d, %s", __LINE__, task->client_ip,
                task->port, ctx->request.header.cmd,
                GET_CMD_CAPTION(ctx->request.header.cmd),
                ctx->request.header.body_len, ctx->response.header.status,
                ctx->response.error.message);
    }

    if (!ctx->need_response) {
        if (sf_handler_ctx.callbacks.get_cmd_log_level != NULL) {
            time_used = get_current_time_us() - ctx->req_start_time;
            log_level = GET_CMD_LOG_LEVEL(ctx->request.header.cmd);
            log_it_ex(&g_log_context, log_level, "file: "__FILE__", line: %d, "
                    "client %s:%u, req cmd: %d (%s), req body_len: %d, "
                    "resp status: %d, time used: %s us", __LINE__,
                    task->client_ip, task->port, ctx->request.header.cmd,
                    GET_CMD_CAPTION(ctx->request.header.cmd),
                    ctx->request.header.body_len, ctx->response.header.status,
                    long_to_comma_str(time_used, time_buff));
        }

        if (ctx->response.header.status == 0) {
            task->offset = task->length = 0;
            return sf_set_read_event(task);
        } else {
            return FC_NEGATIVE(ctx->response.header.status);
        }
    }

    proto_header = (SFCommonProtoHeader *)task->data;
    if (!ctx->response_done) {
        ctx->response.header.body_len = ctx->response.error.length;
        if (ctx->response.error.length > 0) {
            memcpy(task->data + sizeof(SFCommonProtoHeader),
                    ctx->response.error.message, ctx->response.error.length);
        }
    }

    status = sf_unify_errno(FC_ABS(ctx->response.header.status));
    short2buff(status, proto_header->status);
    proto_header->cmd = ctx->response.header.cmd;
    int2buff(ctx->response.header.body_len, proto_header->body_len);
    task->length = sizeof(SFCommonProtoHeader) + ctx->response.header.body_len;

    r = sf_send_add_event(task);
    time_used = get_current_time_us() - ctx->req_start_time;
    if ((sf_handler_ctx.slow_log != NULL) && (sf_handler_ctx.slow_log->
                cfg.enabled && time_used > log_slower_than_us))
    {
        char buff[256];
        int blen;

        blen = sprintf(buff, "timed used: %s us, client %s:%u, "
                "req cmd: %d (%s), req body len: %d, resp cmd: %d (%s), "
                "status: %d, resp body len: %d", long_to_comma_str(time_used,
                    time_buff), task->client_ip, task->port, ctx->request.
                header.cmd, GET_CMD_CAPTION(ctx->request.header.cmd),
                ctx->request.header.body_len, ctx->response.header.cmd,
                GET_CMD_CAPTION(ctx->response.header.cmd),
                ctx->response.header.status, ctx->response.header.body_len);
        log_it_ex2(&sf_handler_ctx.slow_log->ctx, NULL, buff, blen, false, true);
    }

    if (sf_handler_ctx.callbacks.get_cmd_log_level != NULL) {
        log_level = GET_CMD_LOG_LEVEL(ctx->request.header.cmd);
        log_it_ex(&g_log_context, log_level, "file: "__FILE__", line: %d, "
                "client %s:%u, req cmd: %d (%s), req body_len: %d, "
                "resp cmd: %d (%s), status: %d, resp body_len: %d, "
                "time used: %s us", __LINE__,
                task->client_ip, task->port, ctx->request.header.cmd,
                GET_CMD_CAPTION(ctx->request.header.cmd),
                ctx->request.header.body_len, ctx->response.header.cmd,
                GET_CMD_CAPTION(ctx->response.header.cmd),
                ctx->response.header.status, ctx->response.header.body_len,
                long_to_comma_str(time_used, time_buff));
    }

    return r == 0 ? ctx->response.header.status : r;
}
