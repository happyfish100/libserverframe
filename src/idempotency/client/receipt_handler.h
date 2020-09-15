//receipt_handler.h

#ifndef _FS_IDEMPOTENCY_RECEIPT_HANDLER_H
#define _FS_IDEMPOTENCY_RECEIPT_HANDLER_H

#include "client_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int receipt_handler_init();
int receipt_handler_destroy();

#ifdef __cplusplus
}
#endif

#endif
