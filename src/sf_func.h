//sf_func.h

#ifndef _SF_FUNC_H
#define _SF_FUNC_H

#include "fastcommon/common_define.h"
#include "sf_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int sf_connect_to_server(const char *ip_addr, const int port, int *sock);

#ifdef __cplusplus
}
#endif

#endif
