//sf_nio.h

#ifndef _SF_NIO_H
#define _SF_NIO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fastcommon/fast_task_queue.h"
#include "sf_define.h"
#include "sf_types.h"

#ifdef __cplusplus
extern "C" {
#endif

void sf_set_parameters_ex(SFContext *sf_context, const int header_size,
        sf_set_body_length_callback set_body_length_func,
        sf_deal_task_func deal_func, TaskCleanUpCallback cleanup_func,
        sf_recv_timeout_callback timeout_callback);

#define sf_set_parameters(header_size, set_body_length_func, \
        deal_func, cleanup_func, timeout_callback)   \
    sf_set_parameters_ex(&g_sf_context, header_size, \
            set_body_length_func, deal_func, \
            cleanup_func, timeout_callback)

static inline void sf_set_remove_from_ready_list_ex(SFContext *sf_context,
        const bool enabled)
{
    sf_context->remove_from_ready_list = enabled;
}

#define sf_set_remove_from_ready_list(enabled) \
    sf_set_remove_from_ready_list_ex(&g_sf_context, enabled);

static inline TaskCleanUpCallback sf_get_task_cleanup_func_ex(
        SFContext *sf_context)
{
    return sf_context->task_cleanup_func;
}

#define sf_get_task_cleanup_func() \
    sf_get_task_cleanup_func_ex(&g_sf_context)

void sf_recv_notify_read(int sock, short event, void *arg);
int sf_send_add_event(struct fast_task_info *pTask);
int sf_client_sock_write(int sock, short event, void *arg);
int sf_client_sock_read(int sock, short event, void *arg);

void sf_task_finish_clean_up(struct fast_task_info *pTask);

int sf_nio_notify(struct fast_task_info *pTask, const int stage);

void sf_task_switch_thread(struct fast_task_info *pTask,
        const int new_thread_index);

static inline int sf_nio_forward_request(struct fast_task_info *pTask,
        const int new_thread_index)
{
    sf_task_switch_thread(pTask, new_thread_index);
    return sf_nio_notify(pTask, SF_NIO_STAGE_FORWARDED);
}

static inline bool sf_client_sock_in_read_stage(struct fast_task_info *pTask)
{
    return (pTask->event.callback == (IOEventCallback)sf_client_sock_read);
}

#ifdef __cplusplus
}
#endif

#endif
