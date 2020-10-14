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

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <errno.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/sockopt.h"
#include "fastcommon/http_func.h"
#include "sf_define.h"
#include "sf_global.h"
#include "sf_func.h"

int sf_connect_to_server(const char *ip_addr, const int port, int *sock)
{
    int result;
    *sock = socket(AF_INET, SOCK_STREAM, 0);
    if(*sock < 0) {
        return errno != 0 ? errno : ENOMEM;
    }
    tcpsetserveropt(*sock, g_sf_global_vars.network_timeout);

    if ((result=tcpsetnonblockopt(*sock)) != 0) {
        close(*sock);
        *sock = -1;
        return result;
    }

    if ((result=connectserverbyip_nb(*sock, ip_addr, port,
                    g_sf_global_vars.connect_timeout)) != 0)
    {
        close(*sock);
        *sock = -1;
        return result;
    }

    return 0;
}

static void sf_memory_oom_notify_callback(const size_t curr_size)
{
    logCrit("file: "__FILE__", line: %d, "
            "alloc %"PRId64" bytes fail, exiting ...",
            __LINE__, (int64_t)curr_size);
    sf_terminate_myself();
}

void sf_enable_exit_on_oom()
{
    g_oom_notify = sf_memory_oom_notify_callback;
}
