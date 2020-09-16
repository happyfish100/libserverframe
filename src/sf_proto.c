
#include <errno.h>
#include "fastcommon/shared_func.h"
#include "sf_proto.h"

int sf_proto_set_body_length(struct fast_task_info *task)
{
    SFCommonProtoHeader *header;

    header = (SFCommonProtoHeader *)task->data;
    if (!SF_PROTO_CHECK_MAGIC(header->magic)) {
        logError("file: "__FILE__", line: %d, "
                "client ip: %s, magic "SF_PROTO_MAGIC_FORMAT
                " is invalid, expect: "SF_PROTO_MAGIC_FORMAT,
                __LINE__, task->client_ip,
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
        response->error.length = 0;
        response->error.message[0] = '\0';
    }

    return response->header.status;
}

int sf_send_and_recv_response_header(ConnectionInfo *conn, char *data,
        const int len, SFResponseInfo *response, const int network_timeout)
{
    int result;
    SFCommonProtoHeader header_proto;

    if ((result=tcpsenddata_nb(conn->sock, data, len, network_timeout)) != 0) {
        response->error.length = snprintf(response->error.message,
                sizeof(response->error.message),
                "send data fail, errno: %d, error info: %s",
                result, STRERROR(result));
        return result;
    }

    if ((result=tcprecvdata_nb(conn->sock, &header_proto,
            sizeof(SFCommonProtoHeader), network_timeout)) != 0)
    {
        response->error.length = snprintf(response->error.message,
                sizeof(response->error.message),
                "recv data fail, errno: %d, error info: %s",
                result, STRERROR(result));
        return result;
    }

    sf_proto_extract_header(&header_proto, &response->header);
    return 0;
}

int sf_send_and_recv_response(ConnectionInfo *conn, char *send_data,
        const int send_len, SFResponseInfo *response,
        const int network_timeout, const unsigned char expect_cmd,
        char *recv_data, const int expect_body_len)
{
    int result;
    int recv_bytes;

    if ((result=sf_send_and_check_response_header(conn,
                    send_data, send_len, response,
                    network_timeout, expect_cmd)) != 0)
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

    if ((result=tcprecvdata_nb_ex(conn->sock, recv_data,
                    expect_body_len, network_timeout, &recv_bytes)) != 0)
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

int sf_recv_response(ConnectionInfo *conn, SFResponseInfo *response,
        const int network_timeout, const unsigned char expect_cmd,
        char *recv_data, const int expect_body_len)
{
    int result;
    int recv_bytes;
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
    sf_proto_extract_header(&header_proto, &response->header);

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

    if ((result=tcprecvdata_nb_ex(conn->sock, recv_data,
                    expect_body_len, network_timeout, &recv_bytes)) != 0)
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
        case SF_SERVICE_PROTO_REPORT_REQ_RECEIPT_REQ:
            return "REPORT_REQ_RECEIPT_REQ";
        case SF_SERVICE_PROTO_REPORT_REQ_RECEIPT_RESP:
            return "REPORT_REQ_RECEIPT_RESP";
        default:
            return "UNKOWN";
    }
}
