//sf_types.h

#ifndef _SF_TYPES_H_
#define _SF_TYPES_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "connection_pool.h"

struct fast_task_info;
typedef void (*sf_accept_done_callback)(struct fast_task_info *pTask,
        const bool bInnerPort);
typedef int (*sf_set_body_length_callback)(struct fast_task_info *pTask);
typedef int (*sf_deal_task_func)(struct fast_task_info *pTask);
typedef int (*sf_recv_timeout_callback)(struct fast_task_info *pTask);

typedef struct {
    char ip_addr[IP_ADDRESS_SIZE];
    int port;
} SFServerInfo;

#endif

