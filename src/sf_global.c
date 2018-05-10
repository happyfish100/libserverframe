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
#include "shared_func.h"
#include "logger.h"
#include "common_define.h"
#include "sf_define.h"
#include "sf_global.h"

int g_sf_connect_timeout = DEFAULT_CONNECT_TIMEOUT;
int g_sf_network_timeout = DEFAULT_NETWORK_TIMEOUT;
char g_sf_base_path[MAX_PATH_SIZE] = {'/', 't', 'm', 'p', '\0'};

struct nio_thread_data *g_thread_data = NULL;
volatile bool g_continue_flag = true;
int g_outer_port = 0;
int g_inner_port = 0;
int g_max_connections = DEFAULT_MAX_CONNECTONS;
int g_accept_threads = 1;
int g_work_threads = DEFAULT_WORK_THREADS;
int g_thread_stack_size = SF_DEF_THREAD_STACK_SIZE;
int g_max_pkg_size = SF_DEF_MAX_PACKAGE_SIZE;
int g_min_buff_size = SF_DEF_MIN_BUFF_SIZE;
int g_max_buff_size = SF_DEF_MAX_BUFF_SIZE;
int g_sync_log_buff_interval = SYNC_LOG_BUFF_DEF_INTERVAL;

bool g_rotate_error_log = false;
int g_log_file_keep_days = 0;

gid_t g_run_by_gid;
uid_t g_run_by_uid;
char g_run_by_group[32] = {0};
char g_run_by_user[32] = {0};
time_t g_up_time = 0;

char g_inner_bind_addr[IP_ADDRESS_SIZE] = {0};
char g_outer_bind_addr[IP_ADDRESS_SIZE] = {0};

SFConnectionStat g_connection_stat = {0, 0};

int sf_load_config(const char *server_name, const char *filename, 
        IniContext *pIniContext, const int default_inner_port,
        const int default_outer_port)
{
    char *pBasePath;
    char *pBindAddr;
    char *pRunByGroup;
    char *pRunByUser;
    char *pMaxPkgSize;
    char *pMinBuffSize;
    char *pMaxBuffSize;
    char *pThreadStackSize;
    int result;
    int64_t max_pkg_size;
    int64_t min_buff_size;
    int64_t max_buff_size;
    int64_t thread_stack_size;

    pBasePath = iniGetStrValue(NULL, "base_path", pIniContext);
    if (pBasePath == NULL) {
        logError("file: "__FILE__", line: %d, "
                "conf file \"%s\" must have item "
                "\"base_path\"!", __LINE__, filename);
        return ENOENT;
    }

    snprintf(g_sf_base_path, sizeof(g_sf_base_path), "%s", pBasePath);
    chopPath(g_sf_base_path);
    if (!fileExists(g_sf_base_path)) {
        logError("file: "__FILE__", line: %d, "
                "\"%s\" can't be accessed, error info: %s",
                __LINE__, g_sf_base_path, strerror(errno));
        return errno != 0 ? errno : ENOENT;
    }
    if (!isDir(g_sf_base_path)) {
        logError("file: "__FILE__", line: %d, "
                "\"%s\" is not a directory!",
                __LINE__, g_sf_base_path);
        return ENOTDIR;
    }

    g_sf_connect_timeout = iniGetIntValue(NULL, "connect_timeout",
            pIniContext, DEFAULT_CONNECT_TIMEOUT);
    if (g_sf_connect_timeout <= 0) {
        g_sf_connect_timeout = DEFAULT_CONNECT_TIMEOUT;
    }

    g_sf_network_timeout = iniGetIntValue(NULL, "network_timeout",
            pIniContext, DEFAULT_NETWORK_TIMEOUT);
    if (g_sf_network_timeout <= 0) {
        g_sf_network_timeout = DEFAULT_NETWORK_TIMEOUT;
    }

    g_inner_port = iniGetIntValue(NULL, "inner_port", pIniContext,
            default_inner_port);
    if (g_inner_port <= 0) {
        g_inner_port = default_inner_port;
    }
    g_outer_port = iniGetIntValue(NULL, "outer_port", pIniContext,
        default_outer_port);
    if (g_outer_port <= 0) {
        g_outer_port = default_outer_port;
    }

    pBindAddr = iniGetStrValue(NULL, "inner_bind_addr", pIniContext);
    if (pBindAddr == NULL) {
        *g_inner_bind_addr = '\0';
    }
    else {
        snprintf(g_inner_bind_addr, sizeof(g_inner_bind_addr), "%s", pBindAddr);
    }

    pBindAddr = iniGetStrValue(NULL, "outer_bind_addr", pIniContext);
    if (pBindAddr == NULL) {
        *g_outer_bind_addr = '\0';
    }
    else {
        snprintf(g_outer_bind_addr, sizeof(g_outer_bind_addr), "%s", pBindAddr);
    }

    g_max_connections = iniGetIntValue(NULL, "max_connections",
            pIniContext, DEFAULT_MAX_CONNECTONS);
    if (g_max_connections <= 0) {
        g_max_connections = DEFAULT_MAX_CONNECTONS;
    }

    g_accept_threads = iniGetIntValue(NULL, "accept_threads",
            pIniContext, 1);
    if (g_accept_threads <= 0) {
        logError("file: "__FILE__", line: %d, "
                "item \"accept_threads\" is invalid, "
                "value: %d <= 0!", __LINE__, g_accept_threads);
        return EINVAL;
    }

    g_work_threads = iniGetIntValue(NULL, "work_threads",
            pIniContext, DEFAULT_WORK_THREADS);
    if (g_work_threads <= 0) {
        logError("file: "__FILE__", line: %d, "
                "item \"work_threads\" is invalid, "
                "value: %d <= 0!", __LINE__, g_work_threads);
        return EINVAL;
    }

    if ((result=set_rlimit(RLIMIT_NOFILE, g_max_connections)) != 0) {
        return result;
    }

    pMaxPkgSize = iniGetStrValue(NULL,
            "max_pkg_size", pIniContext);
    if (pMaxPkgSize == NULL) {
        max_pkg_size = SF_DEF_MAX_PACKAGE_SIZE;
    }
    else if ((result=parse_bytes(pMaxPkgSize, 1,
                    &max_pkg_size)) != 0)
    {
        return result;
    }
    g_max_pkg_size = (int)max_pkg_size;

    pMinBuffSize = iniGetStrValue(NULL,
            "min_buff_size", pIniContext);
    if (pMinBuffSize == NULL) {
        min_buff_size = SF_DEF_MIN_BUFF_SIZE;
    }
    else if ((result=parse_bytes(pMinBuffSize, 1,
                    &min_buff_size)) != 0)
    {
        return result;
    }
    g_min_buff_size = (int)min_buff_size;

    pMaxBuffSize = iniGetStrValue(NULL,
            "max_buff_size", pIniContext);
    if (pMaxBuffSize == NULL) {
        max_buff_size = SF_DEF_MAX_BUFF_SIZE;
    }
    else if ((result=parse_bytes(pMaxBuffSize, 1,
                    &max_buff_size)) != 0)
    {
        return result;
    }
    g_max_buff_size = (int)max_buff_size;

    if (pMinBuffSize == NULL || pMaxBuffSize == NULL) {
        g_min_buff_size = g_max_pkg_size;
        g_max_buff_size = g_max_pkg_size;
    }
    else if (g_max_buff_size < g_max_pkg_size) {
        g_max_buff_size = g_max_pkg_size;
    }

    pRunByGroup = iniGetStrValue(NULL, "run_by_group", pIniContext);
    pRunByUser = iniGetStrValue(NULL, "run_by_user", pIniContext);
    if (pRunByGroup == NULL) {
        *g_run_by_group = '\0';
    }
    else {
        snprintf(g_run_by_group, sizeof(g_run_by_group),
                "%s", pRunByGroup);
    }
    if (*g_run_by_group == '\0') {
        g_run_by_gid = getegid();
    }
    else {
        struct group *pGroup;

        pGroup = getgrnam(g_run_by_group);
        if (pGroup == NULL) {
            result = errno != 0 ? errno : ENOENT;
            logError("file: "__FILE__", line: %d, "
                    "getgrnam fail, errno: %d, "
                    "error info: %s", __LINE__,
                    result, strerror(result));
            return result;
        }

        g_run_by_gid = pGroup->gr_gid;
    }

    if (pRunByUser == NULL) {
        *g_run_by_user = '\0';
    }
    else {
        snprintf(g_run_by_user, sizeof(g_run_by_user),
                "%s", pRunByUser);
    }
    if (*g_run_by_user == '\0') {
        g_run_by_uid = geteuid();
    }
    else {
        struct passwd *pUser;

        pUser = getpwnam(g_run_by_user);
        if (pUser == NULL) {
            result = errno != 0 ? errno : ENOENT;
            logError("file: "__FILE__", line: %d, "
                    "getpwnam fail, errno: %d, "
                    "error info: %s", __LINE__,
                    result, strerror(result));
            return result;
        }

        g_run_by_uid = pUser->pw_uid;
    }

    if ((result=set_run_by(g_run_by_group, g_run_by_user)) != 0) {
        return result;
    }

    g_sync_log_buff_interval = iniGetIntValue(NULL,
            "sync_log_buff_interval", pIniContext,
            SYNC_LOG_BUFF_DEF_INTERVAL);
    if (g_sync_log_buff_interval <= 0) {
        g_sync_log_buff_interval = SYNC_LOG_BUFF_DEF_INTERVAL;
    }

    pThreadStackSize = iniGetStrValue(NULL,
            "thread_stack_size", pIniContext);
    if (pThreadStackSize == NULL) {
        thread_stack_size = SF_DEF_THREAD_STACK_SIZE;
    }
    else if ((result=parse_bytes(pThreadStackSize, 1,
                    &thread_stack_size)) != 0)
    {
        return result;
    }
    g_thread_stack_size = (int)thread_stack_size;

    g_rotate_error_log = iniGetBoolValue(NULL, "rotate_error_log",
            pIniContext, false);
    g_log_file_keep_days = iniGetIntValue(NULL, "log_file_keep_days",
            pIniContext, 0);

    load_log_level(pIniContext);
    if ((result=log_set_prefix(g_sf_base_path, server_name)) != 0) {
        return result;
    }

    //log_set_time_precision(&g_log_context, LOG_TIME_PRECISION_MSECOND);
    return 0;
}

