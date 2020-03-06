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
#include "fastcommon/common_define.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "sf_define.h"
#include "sf_nio.h"
#include "sf_global.h"

SFGlobalVariables g_sf_global_vars = {
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_NETWORK_TIMEOUT,
    {'/', 't', 'm', 'p', '\0'}, true,
    SF_DEF_THREAD_STACK_SIZE, DEFAULT_MAX_CONNECTONS,
    SF_DEF_MAX_PACKAGE_SIZE, SF_DEF_MIN_BUFF_SIZE, SF_DEF_MAX_BUFF_SIZE,
    SYNC_LOG_BUFF_DEF_INTERVAL, 0, 0, 0, {'\0'}, {'\0'}, false, 0, {0, 0}
};

SFContext g_sf_context = {
    NULL, 0, -1, -1, 0, 0, 1, DEFAULT_WORK_THREADS, 
    {'\0'}, {'\0'}, 0, true, NULL, NULL, sf_task_finish_clean_up,
    NULL
};

static void sf_get_config_str_value(IniContext *pIniContext,
        const char *section_name, const char *item_name,
        char *dest, const int dest_size)
{
    char *value;

    value = iniGetStrValue(section_name, item_name, pIniContext);
    if (value == NULL) {
        *dest = '\0';
    } else {
        snprintf(dest, dest_size, "%s", value);
    }
}

int sf_load_config_ex(const char *server_name, const char *filename,
        IniContext *pIniContext, const char *section_name,
        const int default_inner_port, const int default_outer_port)
{
    char *pBasePath;
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

    snprintf(g_sf_global_vars.base_path, sizeof(g_sf_global_vars.base_path),
            "%s", pBasePath);
    chopPath(g_sf_global_vars.base_path);
    if (!fileExists(g_sf_global_vars.base_path)) {
        logError("file: "__FILE__", line: %d, "
                "\"%s\" can't be accessed, error info: %s",
                __LINE__, g_sf_global_vars.base_path, strerror(errno));
        return errno != 0 ? errno : ENOENT;
    }
    if (!isDir(g_sf_global_vars.base_path)) {
        logError("file: "__FILE__", line: %d, "
                "\"%s\" is not a directory!",
                __LINE__, g_sf_global_vars.base_path);
        return ENOTDIR;
    }

    g_sf_global_vars.connect_timeout = iniGetIntValue(NULL, "connect_timeout",
            pIniContext, DEFAULT_CONNECT_TIMEOUT);
    if (g_sf_global_vars.connect_timeout <= 0) {
        g_sf_global_vars.connect_timeout = DEFAULT_CONNECT_TIMEOUT;
    }

    g_sf_global_vars.network_timeout = iniGetIntValue(NULL, "network_timeout",
            pIniContext, DEFAULT_NETWORK_TIMEOUT);
    if (g_sf_global_vars.network_timeout <= 0) {
        g_sf_global_vars.network_timeout = DEFAULT_NETWORK_TIMEOUT;
    }

    g_sf_global_vars.max_connections = iniGetIntValue(NULL, "max_connections",
            pIniContext, DEFAULT_MAX_CONNECTONS);
    if (g_sf_global_vars.max_connections <= 0) {
        g_sf_global_vars.max_connections = DEFAULT_MAX_CONNECTONS;
    }

    if ((result=set_rlimit(RLIMIT_NOFILE, g_sf_global_vars.
                    max_connections)) != 0)
    {
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
    g_sf_global_vars.max_pkg_size = (int)max_pkg_size;

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
    g_sf_global_vars.min_buff_size = (int)min_buff_size;

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
    g_sf_global_vars.max_buff_size = (int)max_buff_size;

    if (pMinBuffSize == NULL || pMaxBuffSize == NULL) {
        g_sf_global_vars.min_buff_size = g_sf_global_vars.max_pkg_size;
        g_sf_global_vars.max_buff_size = g_sf_global_vars.max_pkg_size;
    }
    else if (g_sf_global_vars.max_buff_size < g_sf_global_vars.max_pkg_size) {
        g_sf_global_vars.max_buff_size = g_sf_global_vars.max_pkg_size;
    }

    pRunByGroup = iniGetStrValue(NULL, "run_by_group", pIniContext);
    pRunByUser = iniGetStrValue(NULL, "run_by_user", pIniContext);
    if (pRunByGroup == NULL) {
        *g_sf_global_vars.run_by_group = '\0';
    }
    else {
        snprintf(g_sf_global_vars.run_by_group,
                sizeof(g_sf_global_vars.run_by_group),
                "%s", pRunByGroup);
    }
    if (*(g_sf_global_vars.run_by_group) == '\0') {
        g_sf_global_vars.run_by_gid = getegid();
    }
    else {
        struct group *pGroup;

        pGroup = getgrnam(g_sf_global_vars.run_by_group);
        if (pGroup == NULL) {
            result = errno != 0 ? errno : ENOENT;
            logError("file: "__FILE__", line: %d, "
                    "getgrnam fail, errno: %d, "
                    "error info: %s", __LINE__,
                    result, strerror(result));
            return result;
        }

        g_sf_global_vars.run_by_gid = pGroup->gr_gid;
    }

    if (pRunByUser == NULL) {
        *g_sf_global_vars.run_by_user = '\0';
    }
    else {
        snprintf(g_sf_global_vars.run_by_user,
                sizeof(g_sf_global_vars.run_by_user),
                "%s", pRunByUser);
    }
    if (*(g_sf_global_vars.run_by_user) == '\0') {
        g_sf_global_vars.run_by_uid = geteuid();
    }
    else {
        struct passwd *pUser;

        pUser = getpwnam(g_sf_global_vars.run_by_user);
        if (pUser == NULL) {
            result = errno != 0 ? errno : ENOENT;
            logError("file: "__FILE__", line: %d, "
                    "getpwnam fail, errno: %d, "
                    "error info: %s", __LINE__,
                    result, strerror(result));
            return result;
        }

        g_sf_global_vars.run_by_uid = pUser->pw_uid;
    }

    if ((result=set_run_by(g_sf_global_vars.run_by_group,
                    g_sf_global_vars.run_by_user)) != 0)
    {
        return result;
    }

    g_sf_global_vars.sync_log_buff_interval = iniGetIntValue(NULL,
            "sync_log_buff_interval", pIniContext,
            SYNC_LOG_BUFF_DEF_INTERVAL);
    if (g_sf_global_vars.sync_log_buff_interval <= 0) {
        g_sf_global_vars.sync_log_buff_interval = SYNC_LOG_BUFF_DEF_INTERVAL;
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
    g_sf_global_vars.thread_stack_size = (int)thread_stack_size;

    g_sf_global_vars.rotate_error_log = iniGetBoolValue(NULL,
            "rotate_error_log", pIniContext, false);
    g_sf_global_vars.log_file_keep_days = iniGetIntValue(NULL,
            "log_file_keep_days", pIniContext, 0);

    load_log_level(pIniContext);
    if ((result=log_set_prefix(g_sf_global_vars.base_path, server_name)) != 0) {
        return result;
    }

    return sf_load_context_from_config(&g_sf_context, filename, pIniContext,
            section_name, default_inner_port, default_outer_port);
}

int sf_load_config(const char *server_name, const char *filename,
        IniContext *pIniContext, const int default_inner_port,
        const int default_outer_port)
{
    return sf_load_config_ex(server_name, filename, pIniContext, "",
            default_inner_port, default_outer_port);
}

int sf_load_context_from_config(SFContext *sf_context,
        const char *filename, IniContext *pIniContext,
        const char *section_name, const int default_inner_port,
        const int default_outer_port)
{
    sf_context->inner_port = iniGetIntValue(section_name,
            "inner_port", pIniContext, default_inner_port);
    sf_context->outer_port = iniGetIntValue(section_name,
            "outer_port", pIniContext, default_outer_port);

    sf_get_config_str_value(pIniContext, section_name,
            "inner_bind_addr", sf_context->inner_bind_addr,
            sizeof(sf_context->inner_bind_addr));
    sf_get_config_str_value(pIniContext, section_name,
            "outer_bind_addr", sf_context->outer_bind_addr,
            sizeof(sf_context->outer_bind_addr));

    sf_context->accept_threads = iniGetIntValue(section_name,
            "accept_threads", pIniContext, 1);
    if (sf_context->accept_threads <= 0) {
        logError("file: "__FILE__", line: %d, "
                "config file: %s, section: %s, "
                "item \"accept_threads\" is invalid, "
                "value: %d <= 0!", __LINE__, filename,
                section_name, sf_context->accept_threads);
        return EINVAL;
    }

    sf_context->work_threads = iniGetIntValue(section_name,
            "work_threads", pIniContext, DEFAULT_WORK_THREADS);
    if (sf_context->work_threads <= 0) {
        logError("file: "__FILE__", line: %d, "
                "config file: %s, section: %s, "
                "item \"work_threads\" is invalid, "
                "value: %d <= 0!", __LINE__, filename,
                section_name, sf_context->work_threads);
        return EINVAL;
    }

    return 0;
}

void sf_log_config_ex(const char *other_config)
{
    char sz_thread_stack_size[32];
    char sz_max_pkg_size[32];
    char sz_min_buff_size[32];
    char sz_max_buff_size[32];

    logInfo("base_path=%s, inner_port=%d, inner_bind_addr=%s, "
            "outer_port=%d, outer_bind_addr=%s, "
            "max_connections=%d, accept_threads=%d, work_threads=%d, "
            "connect_timeout=%d, network_timeout=%d, thread_stack_size=%s, "
            "max_pkg_size=%s, min_buff_size=%s, max_buff_size=%s, "
            "log_level=%s, sync_log_buff_interval=%d, rotate_error_log=%d, "
            "log_file_keep_days=%d, run_by_group=%s, run_by_user=%s%s%s",
            g_sf_global_vars.base_path,
            g_sf_context.inner_port,
            g_sf_context.inner_bind_addr,
            g_sf_context.outer_port,
            g_sf_context.outer_bind_addr,
            g_sf_global_vars.max_connections,
            g_sf_context.accept_threads,
            g_sf_context.work_threads,
            g_sf_global_vars.connect_timeout,
            g_sf_global_vars.network_timeout,
            int_to_comma_str(g_sf_global_vars.thread_stack_size, sz_thread_stack_size),
            int_to_comma_str(g_sf_global_vars.max_pkg_size, sz_max_pkg_size),
            int_to_comma_str(g_sf_global_vars.min_buff_size, sz_min_buff_size),
            int_to_comma_str(g_sf_global_vars.max_buff_size, sz_max_buff_size),
            log_get_level_caption(),
            g_sf_global_vars.sync_log_buff_interval,
            g_sf_global_vars.rotate_error_log,
            g_sf_global_vars.log_file_keep_days,
            g_sf_global_vars.run_by_group,
            g_sf_global_vars.run_by_user,
            (other_config != NULL ? ", " : ""),
            (other_config != NULL ? other_config : "")
            );
}
