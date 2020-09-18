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

#define SF_ERROR_INFO_SIZE   256

#define SF_SERVER_TASK_TYPE_NONE                 0
#define SF_SERVER_TASK_TYPE_CHANNEL_HOLDER     101   //for request idempotency
#define SF_SERVER_TASK_TYPE_CHANNEL_USER       102   //for request idempotency

typedef void (*sf_accept_done_callback)(struct fast_task_info *task,
        const bool bInnerPort);
typedef int (*sf_set_body_length_callback)(struct fast_task_info *task);
typedef int (*sf_deal_task_func)(struct fast_task_info *task);
typedef int (*sf_recv_timeout_callback)(struct fast_task_info *task);

typedef struct sf_context {
    struct nio_thread_data *thread_data;
    volatile int thread_count;
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
    bool realloc_task_buffer;
    sf_deal_task_func deal_task;
    sf_set_body_length_callback set_body_length;
    sf_accept_done_callback accept_done_func;
    TaskCleanUpCallback task_cleanup_func;
    sf_recv_timeout_callback timeout_callback;
} SFContext;

typedef struct {
    int body_len;      //body length
    short flags;
    short status;
    unsigned char cmd; //command
} SFHeaderInfo;

typedef struct {
    SFHeaderInfo header;
    char *body;
} SFRequestInfo;

typedef struct {
    int length;
    char message[SF_ERROR_INFO_SIZE];
} SFErrorInfo;

typedef struct {
    SFHeaderInfo header;
    SFErrorInfo error;
} SFResponseInfo;

#endif
