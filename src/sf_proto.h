//sf_proto.h

#ifndef _FS_IDEMPOTENCY_PROTO_H
#define _FS_IDEMPOTENCY_PROTO_H

#include "fastcommon/fast_task_queue.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/connection_pool.h"
#include "fastcommon/sockopt.h"
#include "sf_types.h"

//for request idempotency
#define FS_SERVICE_PROTO_SETUP_CHANNEL_REQ        51
#define FS_SERVICE_PROTO_SETUP_CHANNEL_RESP       52
#define FS_SERVICE_PROTO_CLOSE_CHANNEL_REQ        53
#define FS_SERVICE_PROTO_CLOSE_CHANNEL_RESP       54
#define FS_SERVICE_PROTO_REPORT_REQ_RECEIPT_REQ   55
#define FS_SERVICE_PROTO_REPORT_REQ_RECEIPT_RESP  56

#define FS_PROTO_MAGIC_CHAR        '@'
#define FS_PROTO_SET_MAGIC(m)   \
    m[0] = m[1] = m[2] = m[3] = FS_PROTO_MAGIC_CHAR

#define FS_PROTO_CHECK_MAGIC(m) \
    (m[0] == FS_PROTO_MAGIC_CHAR && m[1] == FS_PROTO_MAGIC_CHAR && \
     m[2] == FS_PROTO_MAGIC_CHAR && m[3] == FS_PROTO_MAGIC_CHAR)

#define FS_PROTO_MAGIC_FORMAT "0x%02X%02X%02X%02X"
#define FS_PROTO_MAGIC_EXPECT_PARAMS \
    FS_PROTO_MAGIC_CHAR, FS_PROTO_MAGIC_CHAR, \
    FS_PROTO_MAGIC_CHAR, FS_PROTO_MAGIC_CHAR

#define FS_PROTO_MAGIC_PARAMS(m) \
    m[0], m[1], m[2], m[3]

#define FS_PROTO_SET_HEADER(header, _cmd, _body_len) \
    do {  \
        FS_PROTO_SET_MAGIC((header)->magic);   \
        (header)->cmd = _cmd;      \
        (header)->status[0] = (header)->status[1] = 0; \
        int2buff(_body_len, (header)->body_len); \
    } while (0)

#define FS_PROTO_SET_RESPONSE_HEADER(proto_header, resp_header) \
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

typedef struct fs_proto_setup_channel_req {
    char channel_id[4]; //for hint
    char key[4];        //for validate when channel_id > 0
} FSProtoSetupChannelReq;

typedef struct fs_proto_setup_channel_resp {
    char channel_id[4];
    char key[4];
} FSProtoSetupChannelResp;

typedef struct fs_proto_report_req_receipt_header {
    char count[4];
    char padding[4];
} FSProtoReportReqReceiptHeader;

typedef struct fs_proto_report_req_receipt_body {
    char req_id[8];
} FSProtoReportReqReceiptBody;

#ifdef __cplusplus
extern "C" {
#endif

int sf_proto_set_body_length(struct fast_task_info *task);

const char *sf_get_cmd_caption(const int cmd);

static inline void sf_log_network_error_ex(SFResponseInfo *response,
        const ConnectionInfo *conn, const int result, const int line)
{
    if (response->error.length > 0) {
        logError("file: "__FILE__", line: %d, "
                "server %s:%d, %s", line,
                conn->ip_addr, conn->port,
                response->error.message);
    } else {
        logError("file: "__FILE__", line: %d, "
                "communicate with server %s:%d fail, "
                "errno: %d, error info: %s", line,
                conn->ip_addr, conn->port,
                result, STRERROR(result));
    }
}

#define sf_log_network_error(response, conn, result)  \
    sf_log_network_error_ex(response, conn, result, __LINE__)

#ifdef __cplusplus
}
#endif

#endif
