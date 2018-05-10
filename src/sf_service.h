//sf_service.h

#ifndef _SF_SERVICE_H_
#define _SF_SERVICE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ioevent.h"
#include "fast_task_queue.h"
#include "sf_types.h"

typedef void* (*sf_alloc_thread_extra_data_callback)(const int thread_index);

#ifdef __cplusplus
extern "C" {
#endif

extern int g_server_outer_sock;
extern int g_server_inner_sock;

extern int g_worker_thread_count;

int sf_service_init(sf_alloc_thread_extra_data_callback
        alloc_thread_extra_data_callback,
        ThreadLoopCallback thread_loop_callback,
        sf_accept_done_callback accept_done_callback,
        sf_set_body_length_callback set_body_length_func,
        sf_deal_task_func deal_func, TaskCleanUpCallback task_cleanup_func,
        sf_recv_timeout_callback timeout_callback, const int net_timeout_ms,
        const int proto_header_size, const int task_arg_size);
int sf_service_destroy();

int sf_setup_signal_handler();
int sf_socket_server();
void sf_accept_loop();

#ifdef __cplusplus
}
#endif

#endif
