//server_handler.h

#ifndef _SF_IDEMPOTENCY_SERVER_HANDLER_H
#define _SF_IDEMPOTENCY_SERVER_HANDLER_H

#include "server_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int sf_server_deal_setup_channel(struct fast_task_info *task,
        int *task_type, IdempotencyChannel **channel,
        SFResponseInfo *response);

int sf_server_deal_close_channel(struct fast_task_info *task,
        int *task_type, IdempotencyChannel **channel,
        SFResponseInfo *response);

int sf_server_deal_report_req_receipt(struct fast_task_info *task,
        int *task_type, IdempotencyChannel **channel,
        SFResponseInfo *response);

#ifdef __cplusplus
}
#endif

#endif
