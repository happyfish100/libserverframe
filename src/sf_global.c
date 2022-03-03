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
    SF_DEFAULT_CONNECT_TIMEOUT, SF_DEFAULT_NETWORK_TIMEOUT,
    {{'/', 't', 'm', 'p', '\0'}, false},
    true, true, DEFAULT_MAX_CONNECTONS,
    SF_DEF_MAX_PACKAGE_SIZE, SF_DEF_MIN_BUFF_SIZE,
    SF_DEF_MAX_BUFF_SIZE, 0, SF_DEF_THREAD_STACK_SIZE,
    0, 0, 0, {'\0'}, {'\0'}, {SF_DEF_SYNC_LOG_BUFF_INTERVAL, false},
    {0, 0}, NULL, {NULL, 0}
};

SFContext g_sf_context = {
    {'\0'}, NULL, 0, -1, -1, 0, 0, 1, DEFAULT_WORK_THREADS, 
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
    char *pMinBuffSize;
    char *pMaxBuffSize;

    g_sf_global_vars.connect_timeout = iniGetIntValueEx(ini_ctx->
            section_name, "connect_timeout", ini_ctx->context,
            SF_DEFAULT_CONNECT_TIMEOUT, true);
    if (g_sf_global_vars.connect_timeout <= 0) {
        g_sf_global_vars.connect_timeout = SF_DEFAULT_CONNECT_TIMEOUT;
    }

    g_sf_global_vars.network_timeout = iniGetIntValueEx(ini_ctx->
            section_name, "network_timeout", ini_ctx->context,
            SF_DEFAULT_NETWORK_TIMEOUT, true);
    if (g_sf_global_vars.network_timeout <= 0) {
        g_sf_global_vars.network_timeout = SF_DEFAULT_NETWORK_TIMEOUT;
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

    g_sf_global_vars.max_pkg_size = iniGetByteCorrectValueEx(ini_ctx,
            "max_pkg_size", SF_DEF_MAX_PACKAGE_SIZE, 1, 8192,
            SF_MAX_NETWORK_BUFF_SIZE, true);
    pMinBuffSize = iniGetStrValueEx(ini_ctx->section_name,
            "min_buff_size", ini_ctx->context, true);
    pMaxBuffSize = iniGetStrValueEx(ini_ctx->section_name,
            "max_buff_size", ini_ctx->context, true);
    if (pMinBuffSize == NULL || pMaxBuffSize == NULL) {
        g_sf_global_vars.min_buff_size = g_sf_global_vars.max_pkg_size;
        g_sf_global_vars.max_buff_size = g_sf_global_vars.max_pkg_size;
    } else {
        g_sf_global_vars.min_buff_size = iniGetByteCorrectValueEx(ini_ctx,
            "min_buff_size", SF_DEF_MIN_BUFF_SIZE, 1, 8192,
            SF_MAX_NETWORK_BUFF_SIZE, true);
        g_sf_global_vars.max_buff_size = iniGetByteCorrectValueEx(ini_ctx,
            "max_buff_size", SF_DEF_MAX_BUFF_SIZE, 1, 8192,
            SF_MAX_NETWORK_BUFF_SIZE, true);

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
        g_sf_global_vars.max_buff_size += task_buffer_extra_size;
        if (g_sf_global_vars.max_pkg_size < g_sf_global_vars.max_buff_size) {
            g_sf_global_vars.max_pkg_size = g_sf_global_vars.max_buff_size;
        }
    }

    return 0;
}

void sf_set_log_rotate_size(LogContext *log_ctx, const int64_t rotate_on_size)
{
    if (rotate_on_size > 0) {
        log_ctx->rotate_size = rotate_on_size;
        log_set_rotate_time_format(log_ctx, "%Y%m%d_%H%M%S");
    } else {
        log_ctx->rotate_size = 0;
        log_set_rotate_time_format(log_ctx, "%Y%m%d");
    }
}

int sf_load_log_config(IniFullContext *ini_ctx, LogContext *log_ctx,
        SFLogConfig *log_cfg)
{
    int result;

    log_cfg->sync_log_buff_interval = iniGetIntValueEx(
            ini_ctx->section_name, "sync_log_buff_interval",
            ini_ctx->context, SF_DEF_SYNC_LOG_BUFF_INTERVAL, true);
    if (log_cfg->sync_log_buff_interval <= 0) {
        log_cfg->sync_log_buff_interval = SF_DEF_SYNC_LOG_BUFF_INTERVAL;
    }

    log_cfg->rotate_everyday = iniGetBoolValueEx(ini_ctx->section_name,
            "log_file_rotate_everyday", ini_ctx->context, false, true);
    log_cfg->keep_days = iniGetIntValueEx(ini_ctx->section_name,
            "log_file_keep_days", ini_ctx->context, 0, true);
    log_cfg->compress_old = iniGetBoolValueEx(ini_ctx->section_name,
            "log_file_compress_old", ini_ctx->context, false, true);
    log_cfg->compress_days_before = iniGetIntValueEx(ini_ctx->section_name,
            "log_file_compress_days_before", ini_ctx->context, 1, true);
    if (log_cfg->compress_old) {
        log_set_compress_log_flags_ex(log_ctx, LOG_COMPRESS_FLAGS_ENABLED |
                LOG_COMPRESS_FLAGS_NEW_THREAD);
        log_set_compress_log_days_before_ex(log_ctx,
                log_cfg->compress_days_before);
    }

    if ((result=get_time_item_from_conf_ex(ini_ctx, "log_file_rotate_time",
                    &log_cfg->rotate_time, 0, 0, true)) != 0)
    {
        return result;
    }

    if ((result=get_time_item_from_conf_ex(ini_ctx, "log_file_delete_old_time",
                    &log_cfg->delete_old_time, 1, 30, true)) != 0)
    {
        return result;
    }

    log_cfg->rotate_on_size = iniGetByteCorrectValueEx(ini_ctx,
            "log_file_rotate_on_size", 0, 1, 0,
            64 * 1024 * 1024 * 1024LL, true);
    sf_set_log_rotate_size(log_ctx, log_cfg->rotate_on_size);
    return 0;
}

int sf_load_slow_log_config_ex(IniFullContext *ini_ctx, LogContext *log_ctx,
        SFSlowLogConfig *slow_log_cfg)
{
    int result;
    char *filename_prefix;

    if ((result=sf_load_log_config(ini_ctx, log_ctx,
                    &slow_log_cfg->log_cfg)) != 0)
    {
        return result;
    }

    slow_log_cfg->enabled = iniGetBoolValue(ini_ctx->section_name,
            "enabled", ini_ctx->context, false);
    slow_log_cfg->log_slower_than_ms = iniGetIntValue(ini_ctx->section_name,
            "log_slower_than_ms", ini_ctx->context, 100);
    filename_prefix = iniGetStrValue(ini_ctx->section_name,
            "filename_prefix", ini_ctx->context);
    if (filename_prefix == NULL || *filename_prefix == '\0') {
        strcpy(slow_log_cfg->filename_prefix, "slow");
    } else {
        snprintf(slow_log_cfg->filename_prefix,
                sizeof(slow_log_cfg->filename_prefix),
                "%s", filename_prefix);
    }

    return 0;
}

int sf_load_global_base_path(IniFullContext *ini_ctx)
{
    char *pBasePath;

    if (!g_sf_global_vars.base_path.inited) {
        pBasePath = iniGetStrValue(NULL, "base_path", ini_ctx->context);
        if (pBasePath == NULL) {
            logError("file: "__FILE__", line: %d, "
                    "conf file \"%s\" must have item "
                    "\"base_path\"!", __LINE__, ini_ctx->filename);
            return ENOENT;
        }
        sf_set_global_base_path(pBasePath);
    }

    chopPath(SF_G_BASE_PATH_STR);
    if (!fileExists(SF_G_BASE_PATH_STR)) {
        logError("file: "__FILE__", line: %d, "
                "\"%s\" can't be accessed, error info: %s",
                __LINE__, SF_G_BASE_PATH_STR, strerror(errno));
        return errno != 0 ? errno : ENOENT;
    }
    if (!isDir(SF_G_BASE_PATH_STR)) {
        logError("file: "__FILE__", line: %d, "
                "\"%s\" is not a directory!",
                __LINE__, SF_G_BASE_PATH_STR);
        return ENOTDIR;
    }

    return 0;
}

int sf_load_global_config_ex(const char *server_name,
        IniFullContext *ini_ctx, const bool load_network_params,
        const int task_buffer_extra_size)
{
    int result;
    const char *old_section_name;
    char *pRunByGroup;
    char *pRunByUser;

    if ((result=sf_load_global_base_path(ini_ctx)) != 0) {
        return result;
    }

    g_sf_global_vars.task_buffer_extra_size = task_buffer_extra_size;
    g_sf_global_vars.tcp_quick_ack = iniGetBoolValue(NULL,
            "tcp_quick_ack", ini_ctx->context, true);
    tcp_set_quick_ack(g_sf_global_vars.tcp_quick_ack);
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

    g_sf_global_vars.thread_stack_size = iniGetByteCorrectValueEx(ini_ctx,
            "thread_stack_size", SF_DEF_THREAD_STACK_SIZE, 1,
            SF_MIN_THREAD_STACK_SIZE, SF_MAX_THREAD_STACK_SIZE, true);

    old_section_name = ini_ctx->section_name;
    ini_ctx->section_name = "error-log";
    if ((result=sf_load_log_config(ini_ctx, &g_log_context,
                    &g_sf_global_vars.error_log)) != 0)
    {
        return result;
    }
    ini_ctx->section_name = old_section_name;

    load_log_level(ini_ctx->context);
    if (server_name != NULL) {
        if ((result=log_set_prefix(SF_G_BASE_PATH_STR, server_name)) != 0) {
            return result;
        }
    }

    return 0;
}

int sf_load_config_ex(const char *server_name, SFContextIniConfig
        *config, const int task_buffer_extra_size)
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

void sf_log_config_to_string_ex(SFLogConfig *log_cfg, const char *caption,
        const char *other_config, char *output, const int size)
{
    snprintf(output, size,
            "%s: {%s%ssync_log_buff_interval=%d, rotate_everyday=%d, "
            "rotate_time=%02d:%02d, rotate_on_size=%"PRId64", "
            "compress_old=%d, compress_days_before=%d, keep_days=%d, "
            "delete_old_time=%02d:%02d}", caption,
            other_config != NULL ? other_config : "",
            other_config != NULL ? ", " : "",
            log_cfg->sync_log_buff_interval, log_cfg->rotate_everyday,
            log_cfg->rotate_time.hour, log_cfg->rotate_time.minute,
            log_cfg->rotate_on_size, log_cfg->compress_old,
            log_cfg->compress_days_before, log_cfg->keep_days,
            log_cfg->delete_old_time.hour, log_cfg->delete_old_time.minute);
}

void sf_slow_log_config_to_string(SFSlowLogConfig *slow_log_cfg,
        const char *caption, char *output, const int size)
{
    int len;
    char slow_log_buff[256];

    len = snprintf(slow_log_buff, sizeof(slow_log_buff),
            "enabled=%d", slow_log_cfg->enabled);
    if (!slow_log_cfg->enabled) {
        snprintf(output, size, "%s: {%s}",
                caption, slow_log_buff);
        return;
    }

    snprintf(slow_log_buff + len, sizeof(slow_log_buff) - len,
            ", filename_prefix=%s, log_slower_than_ms=%d",
            slow_log_cfg->filename_prefix,
            slow_log_cfg->log_slower_than_ms);

    sf_log_config_to_string_ex(&slow_log_cfg->log_cfg, caption,
            slow_log_buff, output, size);
}

void sf_global_config_to_string(char *output, const int size)
{
    int len;
    int max_pkg_size;
    int min_buff_size;
    int max_buff_size;

    max_pkg_size = g_sf_global_vars.max_pkg_size -
        g_sf_global_vars.task_buffer_extra_size;
    min_buff_size = g_sf_global_vars.min_buff_size -
        g_sf_global_vars.task_buffer_extra_size;
    max_buff_size = g_sf_global_vars.max_buff_size -
        g_sf_global_vars.task_buffer_extra_size;
    len = snprintf(output, size,
            "base_path=%s, max_connections=%d, connect_timeout=%d, "
            "network_timeout=%d, thread_stack_size=%d KB, "
            "max_pkg_size=%d KB, min_buff_size=%d KB, "
            "max_buff_size=%d KB, tcp_quick_ack=%d, log_level=%s, "
            "run_by_group=%s, run_by_user=%s, ", SF_G_BASE_PATH_STR,
            g_sf_global_vars.max_connections,
            g_sf_global_vars.connect_timeout,
            g_sf_global_vars.network_timeout,
            g_sf_global_vars.thread_stack_size / 1024,
            max_pkg_size / 1024, min_buff_size / 1024,
            max_buff_size / 1024,
            g_sf_global_vars.tcp_quick_ack,
            log_get_level_caption(),
            g_sf_global_vars.run_by_group,
            g_sf_global_vars.run_by_user
                );

    sf_log_config_to_string(&g_sf_global_vars.error_log,
            "error-log", output + len, size - len);
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
