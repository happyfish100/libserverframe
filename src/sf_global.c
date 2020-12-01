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
#include <fcntl.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include "fastcommon/common_define.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "sf_nio.h"
#include "sf_global.h"

SFGlobalVariables g_sf_global_vars = {
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_NETWORK_TIMEOUT,
    {'/', 't', 'm', 'p', '\0'}, true, DEFAULT_MAX_CONNECTONS,
    SF_DEF_MAX_PACKAGE_SIZE, SF_DEF_MIN_BUFF_SIZE,
    SF_DEF_MAX_BUFF_SIZE, 0, SF_DEF_THREAD_STACK_SIZE,
    SYNC_LOG_BUFF_DEF_INTERVAL, 0, 0, 0, {'\0'}, {'\0'}, false, 0, {0, 0}
};

SFContext g_sf_context = {
    NULL, 0, -1, -1, 0, 0, 1, DEFAULT_WORK_THREADS, 
    {'\0'}, {'\0'}, 0, true, true, NULL, NULL, NULL,
    sf_task_finish_clean_up, NULL
};

static inline void set_config_str_value(const char *value,
        char *dest, const int dest_size)
{
    if (value == NULL) {
        *dest = '\0';
    } else {
        snprintf(dest, dest_size, "%s", value);
    }
}

static int load_network_parameters(IniFullContext *ini_ctx,
        const int task_buffer_extra_size)
{
    int result;
    char *pMaxPkgSize;
    char *pMinBuffSize;
    char *pMaxBuffSize;
    int64_t max_pkg_size;
    int64_t min_buff_size;
    int64_t max_buff_size;

    g_sf_global_vars.connect_timeout = iniGetIntValueEx(ini_ctx->section_name,
            "connect_timeout", ini_ctx->context, DEFAULT_CONNECT_TIMEOUT, true);
    if (g_sf_global_vars.connect_timeout <= 0) {
        g_sf_global_vars.connect_timeout = DEFAULT_CONNECT_TIMEOUT;
    }

    g_sf_global_vars.network_timeout = iniGetIntValueEx(ini_ctx->section_name,
            "network_timeout", ini_ctx->context, DEFAULT_NETWORK_TIMEOUT, true);
    if (g_sf_global_vars.network_timeout <= 0) {
        g_sf_global_vars.network_timeout = DEFAULT_NETWORK_TIMEOUT;
    }

    g_sf_global_vars.max_connections = iniGetIntValueEx(ini_ctx->section_name,
            "max_connections", ini_ctx->context, DEFAULT_MAX_CONNECTONS, true);
    if (g_sf_global_vars.max_connections <= 0) {
        g_sf_global_vars.max_connections = DEFAULT_MAX_CONNECTONS;
    }

    if ((result=set_rlimit(RLIMIT_NOFILE, g_sf_global_vars.
                    max_connections)) != 0)
    {
        return result;
    }

    pMaxPkgSize = iniGetStrValueEx(ini_ctx->section_name,
            "max_pkg_size", ini_ctx->context, true);
    if (pMaxPkgSize == NULL) {
        max_pkg_size = SF_DEF_MAX_PACKAGE_SIZE;
    }
    else if ((result=parse_bytes(pMaxPkgSize, 1,
                    &max_pkg_size)) != 0)
    {
        return result;
    } else if (max_pkg_size < 8192) {
        logWarning("file: "__FILE__", line: %d, "
                "max_pkg_size: %d is too small, set to 8192",
                __LINE__, (int)max_pkg_size);
        max_pkg_size = 8192;
    }
    g_sf_global_vars.max_pkg_size = (int)max_pkg_size;

    pMinBuffSize = iniGetStrValueEx(ini_ctx->section_name,
            "min_buff_size", ini_ctx->context, true);
    if (pMinBuffSize == NULL) {
        min_buff_size = SF_DEF_MIN_BUFF_SIZE;
    }
    else if ((result=parse_bytes(pMinBuffSize, 1,
                    &min_buff_size)) != 0)
    {
        return result;
    } else if (min_buff_size < 8192) {
        logWarning("file: "__FILE__", line: %d, "
                "min_buff_size: %d is too small, set to 8192",
                __LINE__, (int)min_buff_size);
        min_buff_size = 8192;
    }
    g_sf_global_vars.min_buff_size = (int)min_buff_size;

    pMaxBuffSize = iniGetStrValueEx(ini_ctx->section_name,
            "max_buff_size", ini_ctx->context, true);
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
    else {
        if (g_sf_global_vars.max_buff_size < g_sf_global_vars.max_pkg_size) {
            g_sf_global_vars.max_buff_size = g_sf_global_vars.max_pkg_size;
        }

        if (g_sf_global_vars.max_buff_size < g_sf_global_vars.min_buff_size) {
            logWarning("file: "__FILE__", line: %d, "
                    "max_buff_size: %d < min_buff_size: %d, "
                    "set max_buff_size to min_buff_size", __LINE__,
                    g_sf_global_vars.max_buff_size,
                    g_sf_global_vars.min_buff_size);
            g_sf_global_vars.max_buff_size = g_sf_global_vars.min_buff_size;
        }
    }

    if (task_buffer_extra_size > 0) {
        g_sf_global_vars.min_buff_size += task_buffer_extra_size;
        if (g_sf_global_vars.max_buff_size < g_sf_global_vars.min_buff_size) {
            g_sf_global_vars.max_buff_size = g_sf_global_vars.min_buff_size;
        }
        if (g_sf_global_vars.max_pkg_size < g_sf_global_vars.min_buff_size) {
            g_sf_global_vars.max_pkg_size = g_sf_global_vars.min_buff_size;
        }
    }

    return 0;
}

int sf_load_global_config_ex(const char *server_name,
        IniFullContext *ini_ctx, const bool load_network_params,
        const int task_buffer_extra_size)
{
    int result;
    char *pBasePath;
    char *pRunByGroup;
    char *pRunByUser;
    char *pThreadStackSize;
    int64_t thread_stack_size;

    g_sf_global_vars.task_buffer_extra_size = task_buffer_extra_size;
    pBasePath = iniGetStrValue(NULL, "base_path", ini_ctx->context);
    if (pBasePath == NULL) {
        logError("file: "__FILE__", line: %d, "
                "conf file \"%s\" must have item "
                "\"base_path\"!", __LINE__, ini_ctx->filename);
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

    if (load_network_params) {
        if ((result=load_network_parameters(ini_ctx,
                        task_buffer_extra_size)) != 0)
        {
            return result;
        }
    }

    pRunByGroup = iniGetStrValue(NULL, "run_by_group", ini_ctx->context);
    pRunByUser = iniGetStrValue(NULL, "run_by_user", ini_ctx->context);
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
            "sync_log_buff_interval", ini_ctx->context,
            SYNC_LOG_BUFF_DEF_INTERVAL);
    if (g_sf_global_vars.sync_log_buff_interval <= 0) {
        g_sf_global_vars.sync_log_buff_interval = SYNC_LOG_BUFF_DEF_INTERVAL;
    }

    pThreadStackSize = iniGetStrValueEx(ini_ctx->section_name,
            "thread_stack_size", ini_ctx->context, true);
    if (pThreadStackSize == NULL) {
        thread_stack_size = SF_DEF_THREAD_STACK_SIZE;
    } else if ((result=parse_bytes(pThreadStackSize, 1,
                    &thread_stack_size)) != 0)
    {
        return result;
    } else if (thread_stack_size < SF_MIN_THREAD_STACK_SIZE) {
        logWarning("file: "__FILE__", line: %d, "
                "thread_stack_size : %d is too small, set to %d",
                __LINE__, (int)thread_stack_size, SF_MIN_THREAD_STACK_SIZE);
        thread_stack_size = SF_MIN_THREAD_STACK_SIZE;
    }
    g_sf_global_vars.thread_stack_size = (int)thread_stack_size;

    g_sf_global_vars.rotate_error_log = iniGetBoolValue(NULL,
            "rotate_error_log", ini_ctx->context, false);
    g_sf_global_vars.log_file_keep_days = iniGetIntValue(NULL,
            "log_file_keep_days", ini_ctx->context, 0);

    load_log_level(ini_ctx->context);
    if ((result=log_set_prefix(g_sf_global_vars.base_path, server_name)) != 0) {
        return result;
    }

    return 0;
}

int sf_load_config_ex(const char *server_name,
        SFContextIniConfig *config, const int task_buffer_extra_size)
{
    int result;
    if ((result=sf_load_global_config_ex(server_name, &config->ini_ctx,
                    true, task_buffer_extra_size)) != 0)
    {
        return result;
    }
    return sf_load_context_from_config_ex(&g_sf_context, config);
}

int sf_load_context_from_config_ex(SFContext *sf_context,
        SFContextIniConfig *config)
{
    char *inner_port;
    char *outer_port;
    char *inner_bind_addr;
    char *outer_bind_addr;
    char *bind_addr;
    int port;

    sf_context->inner_port = sf_context->outer_port = 0;

    inner_port = iniGetStrValue(config->ini_ctx.section_name,
            "inner_port", config->ini_ctx.context);
    outer_port = iniGetStrValue(config->ini_ctx.section_name,
            "outer_port", config->ini_ctx.context);
    if (inner_port == NULL && outer_port == NULL) {
        port = iniGetIntValue(config->ini_ctx.section_name,
                "port", config->ini_ctx.context, 0);
        if (port > 0) {
            sf_context->inner_port = sf_context->outer_port = port;
        }
    } else {
        if (inner_port != NULL) {
            sf_context->inner_port = atoi(inner_port);
        }
        if (outer_port != NULL) {
            sf_context->outer_port = atoi(outer_port);
        }
    }

    if (sf_context->inner_port <= 0) {
        sf_context->inner_port = config->default_inner_port;
    }
    if (sf_context->outer_port <= 0) {
        sf_context->outer_port = config->default_outer_port;
    }

    inner_bind_addr = iniGetStrValue(config->ini_ctx.section_name,
            "inner_bind_addr", config->ini_ctx.context);
    outer_bind_addr = iniGetStrValue(config->ini_ctx.section_name,
            "outer_bind_addr", config->ini_ctx.context);
    if (inner_bind_addr == NULL && outer_bind_addr == NULL) {
        bind_addr = iniGetStrValue(config->ini_ctx.section_name,
                "bind_addr", config->ini_ctx.context);
        if (bind_addr != NULL) {
            inner_bind_addr = outer_bind_addr = bind_addr;
        }
    }
    set_config_str_value(inner_bind_addr, sf_context->inner_bind_addr,
                sizeof(sf_context->inner_bind_addr));
    set_config_str_value(outer_bind_addr, sf_context->outer_bind_addr,
                sizeof(sf_context->outer_bind_addr));

    sf_context->accept_threads = iniGetIntValue(
            config->ini_ctx.section_name,
            "accept_threads", config->ini_ctx.context, 1);
    if (sf_context->accept_threads <= 0) {
        logError("file: "__FILE__", line: %d, "
                "config file: %s, section: %s, item \"accept_threads\" "
                "is invalid, value: %d <= 0!", __LINE__, config->
                ini_ctx.filename, config->ini_ctx.section_name,
                sf_context->accept_threads);
        return EINVAL;
    }

    sf_context->work_threads = iniGetIntValue(
            config->ini_ctx.section_name, "work_threads",
            config->ini_ctx.context, config->default_work_threads);
    if (sf_context->work_threads <= 0) {
        logError("file: "__FILE__", line: %d, "
                "config file: %s, section: %s, item \"work_threads\" "
                "is invalid, value: %d <= 0!", __LINE__, config->
                ini_ctx.filename, config->ini_ctx.section_name,
                sf_context->work_threads);
        return EINVAL;
    }

    return 0;
}

void sf_context_config_to_string(const SFContext *sf_context,
        char *output, const int size)
{
    int len;

    len = 0;
    if ((sf_context->inner_port == sf_context->outer_port) &&
            (strcmp(sf_context->inner_bind_addr,
                    sf_context->outer_bind_addr) == 0))
    {
        len += snprintf(output + len, size - len,
                "port=%u, bind_addr=%s",
                sf_context->inner_port,
                sf_context->inner_bind_addr);
    } else {
        len += snprintf(output + len, size - len,
                "inner_port=%u, inner_bind_addr=%s, "
                "outer_port=%u, outer_bind_addr=%s",
                sf_context->inner_port, sf_context->inner_bind_addr,
                sf_context->outer_port, sf_context->outer_bind_addr);
    }

    len += snprintf(output + len, size - len,
            ", accept_threads=%d, work_threads=%d",
            sf_context->accept_threads, sf_context->work_threads);
}

void sf_global_config_to_string(char *output, const int size)
{
    char sz_thread_stack_size[32];
    char sz_max_pkg_size[32];
    char sz_min_buff_size[32];
    char sz_max_buff_size[32];

    snprintf(output, size,
            "base_path=%s, max_connections=%d, connect_timeout=%d, "
            "network_timeout=%d, thread_stack_size=%s, max_pkg_size=%s, "
            "min_buff_size=%s, max_buff_size=%s, task_buffer_extra_size=%d, "
            "log_level=%s, sync_log_buff_interval=%d, rotate_error_log=%d, "
            "log_file_keep_days=%d, run_by_group=%s, run_by_user=%s",
            g_sf_global_vars.base_path,
            g_sf_global_vars.max_connections,
            g_sf_global_vars.connect_timeout,
            g_sf_global_vars.network_timeout,
            int_to_comma_str(g_sf_global_vars.thread_stack_size,
                sz_thread_stack_size),
            int_to_comma_str(g_sf_global_vars.max_pkg_size, sz_max_pkg_size),
            int_to_comma_str(g_sf_global_vars.min_buff_size, sz_min_buff_size),
            int_to_comma_str(g_sf_global_vars.max_buff_size, sz_max_buff_size),
            g_sf_global_vars.task_buffer_extra_size,
            log_get_level_caption(),
            g_sf_global_vars.sync_log_buff_interval,
            g_sf_global_vars.rotate_error_log,
            g_sf_global_vars.log_file_keep_days,
            g_sf_global_vars.run_by_group,
            g_sf_global_vars.run_by_user
                );
}

void sf_log_config_ex(const char *other_config)
{
    char sz_global_config[512];
    char sz_context_config[128];

    sf_global_config_to_string(sz_global_config, sizeof(sz_global_config));
    sf_context_config_to_string(&g_sf_context,
            sz_context_config, sizeof(sz_context_config));

    logInfo("%s, %s%s%s",
            sz_global_config, sz_context_config,
            (other_config != NULL && *other_config != '\0')  ? ", " : "",
            (other_config != NULL) ? other_config : ""
           );
}
