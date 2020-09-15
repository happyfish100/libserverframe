
#include <errno.h>
#include "fastcommon/shared_func.h"
#include "sf_proto.h"

int sf_proto_set_body_length(struct fast_task_info *task)
{
    SFCommonProtoHeader *header;

    header = (SFCommonProtoHeader *)task->data;
    if (!FS_PROTO_CHECK_MAGIC(header->magic)) {
        logError("file: "__FILE__", line: %d, "
                "client ip: %s, magic "FS_PROTO_MAGIC_FORMAT
                " is invalid, expect: "FS_PROTO_MAGIC_FORMAT,
                __LINE__, task->client_ip,
                FS_PROTO_MAGIC_PARAMS(header->magic),
                FS_PROTO_MAGIC_EXPECT_PARAMS);
        return EINVAL;
    }

    task->length = buff2int(header->body_len); //set body length
    return 0;
}
const char *sf_get_cmd_caption(const int cmd)
{
    switch (cmd) {
        case FS_SERVICE_PROTO_SETUP_CHANNEL_REQ:
            return "SETUP_CHANNEL_REQ";
        case FS_SERVICE_PROTO_SETUP_CHANNEL_RESP:
            return "SETUP_CHANNEL_RESP";
        case FS_SERVICE_PROTO_CLOSE_CHANNEL_REQ:
            return "CLOSE_CHANNEL_REQ";
        case FS_SERVICE_PROTO_CLOSE_CHANNEL_RESP:
            return "CLOSE_CHANNEL_RESP";
        case FS_SERVICE_PROTO_REPORT_REQ_RECEIPT_REQ:
            return "REPORT_REQ_RECEIPT_REQ";
        case FS_SERVICE_PROTO_REPORT_REQ_RECEIPT_RESP:
            return "REPORT_REQ_RECEIPT_RESP";
        default:
            return "UNKOWN";
    }
}
