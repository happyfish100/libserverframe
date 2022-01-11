/*
 * Copyright (c) 2020 YuQing <384681@qq.com>
 *
 * This program is free software: you can use, redistribute, and/or modify
 * it under the terms of the GNU Affero General Public License, version 3
 * or later ("AGPL"), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

//sf_func.h

#ifndef _SF_FUNC_H
#define _SF_FUNC_H

#include "fastcommon/pthread_func.h"
#include "fastcommon/fc_atomic.h"
#include "sf_types.h"
#include "sf_global.h"

#ifdef __cplusplus
extern "C" {
#endif

int sf_connect_to_server(const char *ip_addr, const int port, int *sock);

#define sf_terminate_myself() \
    sf_terminate_myself_ex(__FILE__, __LINE__, __FUNCTION__)

static inline void sf_terminate_myself_ex(const char *file,
        const int line, const char *func)
{
    g_sf_global_vars.continue_flag = false;
    if (kill(getpid(), SIGQUIT) == 0) { //signal myself to quit
        logInfo("file: "__FILE__", line: %d, "
                "kill myself from caller {file: %s, line: %d, func: %s}",
                __LINE__, file, line, func);
    } else {
        logError("file: "__FILE__", line: %d, "
                "kill myself fail, errno: %d, error info: %s",
                __LINE__, errno, strerror(errno));
    }
}

void sf_enable_exit_on_oom();

static inline int sf_binlog_buffer_init(SFBinlogBuffer *buffer, const int size)
{
    buffer->buff = (char *)fc_malloc(size);
    if (buffer->buff == NULL) {
        return ENOMEM;
    }

    buffer->current = buffer->end = buffer->buff;
    buffer->size = size;
    return 0;
}

static inline void sf_binlog_buffer_destroy(SFBinlogBuffer *buffer)
{
    if (buffer->buff != NULL) {
        free(buffer->buff);
        buffer->current = buffer->end = buffer->buff = NULL;
        buffer->size = 0;
    }
}

static inline int sf_synchronize_ctx_init(SFSynchronizeContext *sctx)
{
    sctx->waiting_count = 0;
    return init_pthread_lock_cond_pair(&sctx->lcp);
}

static inline void sf_synchronize_counter_add(
        SFSynchronizeContext *sctx, const int count)
{
    PTHREAD_MUTEX_LOCK(&sctx->lcp.lock);
    sctx->waiting_count += count;
    PTHREAD_MUTEX_UNLOCK(&sctx->lcp.lock);
}

static inline void sf_synchronize_counter_sub(
        SFSynchronizeContext *sctx, const int count)
{
    PTHREAD_MUTEX_LOCK(&sctx->lcp.lock);
    sctx->waiting_count -= count;
    PTHREAD_MUTEX_UNLOCK(&sctx->lcp.lock);
}

static inline void sf_synchronize_counter_notify(
        SFSynchronizeContext *sctx, const int count)
{
    PTHREAD_MUTEX_LOCK(&sctx->lcp.lock);
    sctx->waiting_count -= count;
    if (sctx->waiting_count == 0) {
        pthread_cond_signal(&sctx->lcp.cond);
    }
    PTHREAD_MUTEX_UNLOCK(&sctx->lcp.lock);
}

static inline void sf_synchronize_counter_wait(SFSynchronizeContext *sctx)
{
    PTHREAD_MUTEX_LOCK(&sctx->lcp.lock);
    while (sctx->waiting_count != 0 && SF_G_CONTINUE_FLAG) {
        pthread_cond_wait(&sctx->lcp.cond, &sctx->lcp.lock);
    }
    PTHREAD_MUTEX_UNLOCK(&sctx->lcp.lock);
}

#ifdef __cplusplus
}
#endif

#endif
