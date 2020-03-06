//sf_types.h

#ifndef _SF_TYPES_H_
#define _SF_TYPES_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "fastcommon/connection_pool.h"
#include "fastcommon/fast_task_queue.h"

typedef void (*sf_accept_done_callback)(struct fast_task_info *pTask,
        const bool bInnerPort);
typedef int (*sf_set_body_length_callback)(struct fast_task_info *pTask);
typedef int (*sf_deal_task_func)(struct fast_task_info *pTask);
typedef int (*sf_recv_timeout_callback)(struct fast_task_info *pTask);

typedef struct sf_context {
    struct nio_thread_data *thread_data;
    int thread_count;
    int outer_sock;
    int inner_sock;

    int outer_port;
    int inner_port;
    int accept_threads;
    int work_threads;

    char inner_bind_addr[IP_ADDRESS_SIZE];
    char outer_bind_addr[IP_ADDRESS_SIZE];

    int header_size;
    bool remove_from_ready_list;
    sf_deal_task_func deal_task;
    sf_set_body_length_callback set_body_length;
    TaskCleanUpCallback task_cleanup_func;
    sf_recv_timeout_callback timeout_callback;
    sf_accept_done_callback accept_done_func;
} SFContext;

#endif

