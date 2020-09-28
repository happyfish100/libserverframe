//sf_func.h

#ifndef _SF_FUNC_H
#define _SF_FUNC_H

#include "fastcommon/common_define.h"
#include "sf_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int sf_connect_to_server(const char *ip_addr, const int port, int *sock);

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

#ifdef __cplusplus
}
#endif

#endif
