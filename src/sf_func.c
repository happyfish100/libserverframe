#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/sockopt.h"
#include "fastcommon/http_func.h"
#include "sf_define.h"
#include "sf_global.h"
#include "sf_func.h"

int sf_parse_server_info(const char* pServerStr, SFServerInfo* pServerInfo,
                         const int default_port)
{
    char *parts[2];
    char server_info[256];
    int len;
    int count;

    len = strlen(pServerStr);
    if (len == 0) {
        logError("file: "__FILE__", line: %d, "
            "pServerStr \"%s\" is empty!",
            __LINE__, pServerStr);
        return EINVAL;
    }
    if (len >= sizeof(server_info)) {
        logError("file: "__FILE__", line: %d, "
            "pServerStr \"%s\" is too long!",
            __LINE__, pServerStr);
        return ENAMETOOLONG;
    }

    memcpy(server_info, pServerStr, len);
    *(server_info + len) = '\0';

    count = splitEx(server_info, ':', parts, 2);
    if (count == 1) {
        pServerInfo->port = default_port;
    }
    else {
        char *endptr = NULL;
        pServerInfo->port = (int)strtol(parts[1], &endptr, 10);
        if ((endptr != NULL && *endptr != '\0') || pServerInfo->port <= 0) {
            logError("file: "__FILE__", line: %d, "
                "pServerStr: %s, invalid port: %s!",
                __LINE__, pServerStr, parts[1]);
            return EINVAL;
        }
    }

    if (getIpaddrByName(parts[0], pServerInfo->ip_addr,
        sizeof(pServerInfo->ip_addr)) == INADDR_NONE)
    {
        logError("file: "__FILE__", line: %d, "
            "pServerStr: %s, invalid hostname: %s!",
            __LINE__, pServerStr, parts[0]);
        return EINVAL;
    }
    
    return 0;
}

int sf_load_server_info(IniContext *pIniContext, const char *filename,
        const char *item_name, SFServerInfo *pServerInfo,
        const int default_port)
{
    char *pServerStr;

	pServerStr = iniGetStrValue(NULL, item_name, pIniContext);
    if (pServerStr == NULL) {
        logError("file: "__FILE__", line: %d, "
                "config file: %s, item \"%s\" not exist!",
                __LINE__, filename, item_name);
        return ENOENT;
    }

    return sf_parse_server_info(pServerStr, pServerInfo, default_port);
}

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

