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
#include <dlfcn.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include "fastcommon/common_define.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/process_ctrl.h"
#include "fastcommon/local_ip_func.h"
#include "fastcommon/logger.h"
#include "sf_nio.h"
#include "sf_service.h"
#include "sf_global.h"

SFGlobalVariables g_sf_global_vars = {
    {{'/', 't', 'm', 'p', '\0'}, false},
    true, true, false, { SF_DEFAULT_CONNECT_TIMEOUT,
        SF_DEFAULT_NETWORK_TIMEOUT, DEFAULT_MAX_CONNECTONS,
    SF_DEF_MAX_PACKAGE_SIZE, SF_DEF_MIN_BUFF_SIZE,
    SF_DEF_MAX_BUFF_SIZE}, 0, SF_DEF_THREAD_STACK_SIZE, 0,
    {false, 0, 0, {'\0'}, {'\0'}},
    {SF_DEF_SYNC_LOG_BUFF_INTERVAL, false},
    {0, 0}, NULL, {NULL, 0}
};

SFContext g_sf_context = {{'\0'}, NULL, 0, false, sf_address_family_auto,
    {{AF_UNSPEC, {{true, fc_comm_type_sock}, {false, fc_comm_type_rdma}}},
        {AF_UNSPEC, {{true, fc_comm_type_sock}, {false, fc_comm_type_rdma}}}},
    {DEFAULT_MAX_CONNECTONS, SF_DEF_MAX_PACKAGE_SIZE, SF_DEF_MIN_BUFF_SIZE,
    SF_DEF_MAX_BUFF_SIZE}, 1, DEFAULT_WORK_THREADS, 0, true, true,
    {false, 0, 0}, {sf_task_finish_clean_up}
};

static int load_network_parameters(IniFullContext *ini_ctx,
        const char *max_pkg_size_item_nm, const int max_pkg_size_min_value,
        const int fixed_buff_size, const int task_buffer_extra_size,
        SFNetBufferConfig *net_buffer_cfg)
{
    int padding_buff_size;
    char *pMinBuffSize;
    char *pMaxBuffSize;

    net_buffer_cfg->connect_timeout = iniGetIntValueEx(ini_ctx->
            section_name, "connect_timeout", ini_ctx->context,
            SF_DEFAULT_CONNECT_TIMEOUT, true);
    if (net_buffer_cfg->connect_timeout <= 0) {
        net_buffer_cfg->connect_timeout = SF_DEFAULT_CONNECT_TIMEOUT;
    }

    net_buffer_cfg->network_timeout = iniGetIntValueEx(ini_ctx->
            section_name, "network_timeout", ini_ctx->context,
            SF_DEFAULT_NETWORK_TIMEOUT, true);
    if (net_buffer_cfg->network_timeout <= 0) {
        net_buffer_cfg->network_timeout = SF_DEFAULT_NETWORK_TIMEOUT;
    }

    net_buffer_cfg->max_connections = iniGetIntValueEx(ini_ctx->section_name,
            "max_connections", ini_ctx->context, DEFAULT_MAX_CONNECTONS, true);
    if (net_buffer_cfg->max_connections <= 0) {
        net_buffer_cfg->max_connections = DEFAULT_MAX_CONNECTONS;
    }

    if (fixed_buff_size > 0) {
        padding_buff_size = FC_MAX(fixed_buff_size, max_pkg_size_min_value) +
            task_buffer_extra_size;
        net_buffer_cfg->min_buff_size = padding_buff_size;
        net_buffer_cfg->max_buff_size = padding_buff_size;
        net_buffer_cfg->max_pkg_size = padding_buff_size;
        return 0;
    }

    net_buffer_cfg->max_pkg_size = iniGetByteCorrectValueEx(ini_ctx,
            max_pkg_size_item_nm, SF_DEF_MAX_PACKAGE_SIZE, 1, 8192,
            SF_MAX_NETWORK_BUFF_SIZE, true);
    if (net_buffer_cfg->max_pkg_size < max_pkg_size_min_value) {
        net_buffer_cfg->max_pkg_size = max_pkg_size_min_value;
    }
    if (task_buffer_extra_size > 0) {
        net_buffer_cfg->max_pkg_size += task_buffer_extra_size;
    }

    pMinBuffSize = iniGetStrValueEx(ini_ctx->section_name,
            "min_buff_size", ini_ctx->context, true);
    pMaxBuffSize = iniGetStrValueEx(ini_ctx->section_name,
            "max_buff_size", ini_ctx->context, true);
    if (pMinBuffSize == NULL || pMaxBuffSize == NULL) {
        net_buffer_cfg->min_buff_size = net_buffer_cfg->max_pkg_size;
        net_buffer_cfg->max_buff_size = net_buffer_cfg->max_pkg_size;
    } else {
        net_buffer_cfg->min_buff_size = iniGetByteCorrectValueEx(ini_ctx,
            "min_buff_size", SF_DEF_MIN_BUFF_SIZE, 1, 4096,
            SF_MAX_NETWORK_BUFF_SIZE, true);
        net_buffer_cfg->max_buff_size = iniGetByteCorrectValueEx(ini_ctx,
            "max_buff_size", SF_DEF_MAX_BUFF_SIZE, 1, 8192,
            SF_MAX_NETWORK_BUFF_SIZE, true);

        if (task_buffer_extra_size > 0) {
            net_buffer_cfg->min_buff_size += task_buffer_extra_size;
            net_buffer_cfg->max_buff_size += task_buffer_extra_size;
        }
        if (net_buffer_cfg->max_buff_size < net_buffer_cfg->max_pkg_size) {
            net_buffer_cfg->max_buff_size = net_buffer_cfg->max_pkg_size;
        } else if (net_buffer_cfg->max_pkg_size <
                net_buffer_cfg->max_buff_size)
        {
            net_buffer_cfg->max_pkg_size = net_buffer_cfg->max_buff_size;
        }
        if (net_buffer_cfg->max_buff_size < net_buffer_cfg->min_buff_size) {
            logWarning("file: "__FILE__", line: %d, "
                    "max_buff_size: %d < min_buff_size: %d, "
                    "set max_buff_size to min_buff_size", __LINE__,
                    net_buffer_cfg->max_buff_size,
                    net_buffer_cfg->min_buff_size);
            net_buffer_cfg->max_buff_size = net_buffer_cfg->min_buff_size;
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
            "log_file_rotate_everyday", ini_ctx->context, true, true);
    log_cfg->keep_days = iniGetIntValueEx(ini_ctx->section_name,
            "log_file_keep_days", ini_ctx->context, 15, true);
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
        fc_safe_strcpy(slow_log_cfg->filename_prefix, filename_prefix);
    }

    return 0;
}

int sf_get_base_path_from_conf_file(const char *config_filename)
{
    int result;

    if (SF_G_BASE_PATH_INITED) {
        return 0;
    }

    result = get_base_path_from_conf_file_ex(config_filename,
            SF_G_BASE_PATH_STR, sizeof(SF_G_BASE_PATH_STR), LOG_NOTHING);
    if (result != 0) {
        if (result == ENOENT) {
            if ((result=fc_check_mkdir_ex(SF_G_BASE_PATH_STR,
                            0775, &SF_G_BASE_PATH_CREATED)) != 0)
            {
                return result;
            }
        } else {
            return result;
        }
    }

    SF_G_BASE_PATH_LEN = strlen(SF_G_BASE_PATH_STR);
    SF_G_BASE_PATH_INITED = true;
    return 0;
}

int sf_load_global_base_path(IniFullContext *ini_ctx)
{
    int result;
    char *pBasePath;

    if (!SF_G_BASE_PATH_INITED) {
        pBasePath = iniGetStrValue(NULL, "base_path", ini_ctx->context);
        if (pBasePath == NULL || *pBasePath == '\0') {
            logError("file: "__FILE__", line: %d, "
                    "conf file \"%s\" must have item "
                    "\"base_path\"!", __LINE__, ini_ctx->filename);
            return ENOENT;
        }
        sf_set_global_base_path(pBasePath);
    }

    chopPath(SF_G_BASE_PATH_STR);
    SF_G_BASE_PATH_LEN = strlen(SF_G_BASE_PATH_STR);
    if (!fileExists(SF_G_BASE_PATH_STR)) {
        if ((result=fc_check_mkdir_ex(SF_G_BASE_PATH_STR, 0775,
                        &SF_G_BASE_PATH_CREATED)) != 0)
        {
            return result;
        }
    }
    if (!isDir(SF_G_BASE_PATH_STR)) {
        logError("file: "__FILE__", line: %d, "
                "\"%s\" is not a directory!",
                __LINE__, SF_G_BASE_PATH_STR);
        return ENOTDIR;
    }

    return 0;
}

int sf_load_global_config_ex(const char *log_filename_prefix,
        IniFullContext *ini_ctx, const bool load_network_params,
        const char *max_pkg_size_item_nm, const int fixed_buff_size,
        const int task_buffer_extra_size, const bool need_set_run_by)
{
    const int max_pkg_size_min_value = 0;
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
        if ((result=load_network_parameters(ini_ctx, max_pkg_size_item_nm,
                        max_pkg_size_min_value, fixed_buff_size,
                        task_buffer_extra_size, &g_sf_global_vars.
                        net_buffer_cfg)) != 0)
        {
            return result;
        }

        if ((result=set_rlimit(RLIMIT_NOFILE, g_sf_global_vars.
                        net_buffer_cfg.max_connections)) != 0)
        {
            return result;
        }
    }

    pRunByGroup = iniGetStrValue(NULL, "run_by_group", ini_ctx->context);
    pRunByUser = iniGetStrValue(NULL, "run_by_user", ini_ctx->context);
    if (pRunByGroup == NULL) {
        *g_sf_global_vars.run_by.group = '\0';
    }
    else {
        fc_safe_strcpy(g_sf_global_vars.run_by.group, pRunByGroup);
    }
    if (*(g_sf_global_vars.run_by.group) == '\0') {
        g_sf_global_vars.run_by.gid = getegid();
    }
    else {
        struct group *pGroup;

        pGroup = getgrnam(g_sf_global_vars.run_by.group);
        if (pGroup == NULL) {
            result = errno != 0 ? errno : ENOENT;
            logError("file: "__FILE__", line: %d, "
                    "getgrnam fail, errno: %d, "
                    "error info: %s", __LINE__,
                    result, strerror(result));
            return result;
        }

        g_sf_global_vars.run_by.gid = pGroup->gr_gid;
    }

    if (pRunByUser == NULL) {
        *g_sf_global_vars.run_by.user = '\0';
    }
    else {
        fc_safe_strcpy(g_sf_global_vars.run_by.user, pRunByUser);
    }
    if (*(g_sf_global_vars.run_by.user) == '\0') {
        g_sf_global_vars.run_by.uid = geteuid();
    }
    else {
        struct passwd *pUser;

        pUser = getpwnam(g_sf_global_vars.run_by.user);
        if (pUser == NULL) {
            result = errno != 0 ? errno : ENOENT;
            logError("file: "__FILE__", line: %d, "
                    "getpwnam fail, errno: %d, "
                    "error info: %s", __LINE__,
                    result, strerror(result));
            return result;
        }

        g_sf_global_vars.run_by.uid = pUser->pw_uid;
    }
    g_sf_global_vars.run_by.inited = true;

    if (SF_G_BASE_PATH_CREATED) {
        SF_CHOWN_TO_RUNBY_RETURN_ON_ERROR(SF_G_BASE_PATH_STR);
    }

    if (need_set_run_by) {
        if ((result=set_run_by(g_sf_global_vars.run_by.group,
                        g_sf_global_vars.run_by.user)) != 0)
        {
            return result;
        }
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
    if (log_filename_prefix != NULL) {
        if ((result=log_set_prefix(SF_G_BASE_PATH_STR,
                        log_filename_prefix)) != 0)
        {
            return result;
        }
    }

    return 0;
}

int sf_load_config_ex(const char *log_filename_prefix,
        SFContextIniConfig *config, const int fixed_buff_size,
        const int task_buffer_extra_size, const bool need_set_run_by)
{
    int result;
    if ((result=sf_load_global_config_ex(log_filename_prefix, &config->ini_ctx,
                    true, config->max_pkg_size_item_name, fixed_buff_size,
                    task_buffer_extra_size, need_set_run_by)) != 0)
    {
        return result;
    }
    return sf_load_context_from_config_ex(&g_sf_context, config,
            fixed_buff_size, task_buffer_extra_size);
}

#define API_PREFIX_NAME  "fast_rdma_"

#define LOAD_API_EX(handler, prefix, fname) \
    do { \
        handler->fname = dlsym(dlhandle, API_PREFIX_NAME#prefix#fname); \
        if (handler->fname == NULL) {  \
            logError("file: "__FILE__", line: %d, "  \
                    "dlsym api %s fail, error info: %s", \
                    __LINE__, API_PREFIX_NAME#prefix#fname, dlerror()); \
            return ENOENT; \
        } \
    } while (0)

#define LOAD_API(handler, fname)  LOAD_API_EX(handler, server_, fname)

static int load_rdma_apis(SFContext *sf_context, SFNetworkHandler *handler)
{
    const char *library = "libfastrdma.so";
    void *dlhandle;

    dlhandle = dlopen(library, RTLD_LAZY);
    if (dlhandle == NULL) {
        logError("file: "__FILE__", line: %d, "
                "dlopen %s fail, error info: %s",
                __LINE__, library, dlerror());
        return EFAULT;
    }

    LOAD_API(handler, get_connection_size);
    LOAD_API(handler, init_connection);
    if (sf_context->is_client) {
        LOAD_API_EX(handler, client_, alloc_pd);
    } else {
        LOAD_API(handler, alloc_pd);
    }
    LOAD_API_EX(handler, , create_server);
    LOAD_API_EX(handler, , close_server);
    LOAD_API(handler, accept_connection);
    LOAD_API_EX(handler, , async_connect_server);
    LOAD_API_EX(handler, , async_connect_check);
    LOAD_API(handler, close_connection);
    LOAD_API(handler, send_data);
    LOAD_API(handler, recv_data);
    LOAD_API(handler, post_recv);

    return 0;
}

static int init_network_handler(SFContext *sf_context,
        SFNetworkHandler *handler, SFAddressFamilyHandler *fh,
        const bool use_send_zc)
{
    handler->fh = fh;
    handler->inner.handler = handler;
    handler->outer.handler = handler;
    handler->inner.is_inner = true;
    handler->outer.is_inner = false;
    handler->explicit_post_recv = false;

    if (handler->comm_type == fc_comm_type_sock) {
        handler->inner.sock = -1;
        handler->outer.sock = -1;
        handler->create_server = sf_socket_create_server;
        handler->close_server = sf_socket_close_server;
        handler->accept_connection = sf_socket_accept_connection;
        handler->async_connect_server = sf_socket_async_connect_server;
        handler->async_connect_check = sf_socket_async_connect_check;
        handler->close_connection = sf_socket_close_connection;
        handler->send_data = sf_socket_send_data;
        handler->recv_data = sf_socket_recv_data;
        handler->post_recv = NULL;
#if IOEVENT_USE_URING
        handler->use_io_uring = true;
        handler->use_send_zc = use_send_zc;
#else
        handler->use_io_uring = false;
        handler->use_send_zc = false;
#endif
        return 0;
    } else {
        handler->inner.id = NULL;
        handler->outer.id = NULL;
        handler->use_io_uring = false;
        return load_rdma_apis(sf_context, handler);
    }
}

static void set_bind_address(const char *bind_addr, char *ipv4_bind_addr,
        char *ipv6_bind_addr, const int addr_size)
{
    char new_bind_addr[2 * IP_ADDRESS_SIZE];
    char *cols[2];
    char *ip_addr;
    int count;
    int len;
    int i;

    if (bind_addr == NULL || *bind_addr == '\0') {
        *ipv4_bind_addr = *ipv6_bind_addr = '\0';
        return;
    }

    fc_safe_strcpy(new_bind_addr, bind_addr);
    count = splitEx(new_bind_addr, ',', cols, 2);
    for (i=0; i<count; i++) {
        ip_addr = cols[i];
        if (is_ipv6_addr(ip_addr)) {
            len = strlen(ip_addr);
            if (*ip_addr == '[' && *(ip_addr + (len - 1)) == ']') {
                ++ip_addr;
                len -= 2;
            }
            if (len >= addr_size) {
                len = addr_size - 1;
            }
            memcpy(ipv6_bind_addr, ip_addr, len);
            *(ipv6_bind_addr + len) = '\0';
        } else {
            fc_strlcpy(ipv4_bind_addr, ip_addr, addr_size);
        }
    }
}

static int load_bind_address(SFContext *sf_context,
        SFContextIniConfig *config)
{
    char *inner_bind_addr;
    char *outer_bind_addr;
    char *bind_addr;
    SFAddressFamilyHandler *ipv4_handler;
    SFAddressFamilyHandler *ipv6_handler;

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

    ipv4_handler = sf_context->handlers + SF_IPV4_ADDRESS_FAMILY_INDEX;
    ipv6_handler = sf_context->handlers + SF_IPV6_ADDRESS_FAMILY_INDEX;
    set_bind_address(inner_bind_addr, ipv4_handler->inner_bind_addr,
            ipv6_handler->inner_bind_addr,
            sizeof(ipv4_handler->inner_bind_addr));
    set_bind_address(outer_bind_addr, ipv4_handler->outer_bind_addr,
            ipv6_handler->outer_bind_addr,
            sizeof(ipv4_handler->outer_bind_addr));
    return 0;
}

static int load_address_family(SFContext *sf_context,
        SFContextIniConfig *config)
{
    char *address_family_str;
    SFAddressFamily address_family;
    SFAddressFamilyHandler *ipv4_handler;
    SFAddressFamilyHandler *ipv6_handler;
    bool ipv4_bound;
    bool ipv6_bound;

    address_family_str = iniGetStrValue(config->ini_ctx.section_name,
            "address_family", config->ini_ctx.context);
    if (address_family_str == NULL) {
        sf_context->address_family = sf_address_family_auto;
    } else if (strcasecmp(address_family_str, "auto") == 0) {
        sf_context->address_family = sf_address_family_auto;
    } else if (strcasecmp(address_family_str, "IPv4") == 0) {
        sf_context->address_family = sf_address_family_ipv4;
    } else if (strcasecmp(address_family_str, "IPv6") == 0) {
        sf_context->address_family = sf_address_family_ipv6;
    } else if (strcasecmp(address_family_str, "both") == 0) {
        sf_context->address_family = sf_address_family_both;
    } else {
        logError("file: "__FILE__", line: %d, "
                "config file: %s, section: %s, address_family: %s "
                "is invalid!", __LINE__, config->ini_ctx.filename,
                config->ini_ctx.section_name, address_family_str);
        return EINVAL;
    }

    ipv4_handler = sf_context->handlers + SF_IPV4_ADDRESS_FAMILY_INDEX;
    ipv6_handler = sf_context->handlers + SF_IPV6_ADDRESS_FAMILY_INDEX;
    if (sf_context->address_family == sf_address_family_auto) {
        ipv4_bound = (*ipv4_handler->inner_bind_addr != '\0' ||
                *ipv4_handler->outer_bind_addr != '\0');
        ipv6_bound = (*ipv6_handler->inner_bind_addr != '\0' ||
                *ipv6_handler->outer_bind_addr != '\0');
        if (ipv4_bound) {
            if (ipv6_bound) {
                address_family = sf_address_family_both;
            } else {
                address_family = sf_address_family_ipv4;
            }
        } else {
            if (ipv6_bound) {
                address_family = sf_address_family_ipv6;
            } else {
                int ipv4_count;
                int ipv6_count;
                stat_local_host_ip(&ipv4_count, &ipv6_count);
                if (ipv4_count > 0) {
                    address_family = sf_address_family_ipv4;
                } else {
                    address_family = sf_address_family_ipv6;
                }
            }
        }
    } else {
        address_family = sf_context->address_family;
    }

    switch (address_family) {
        case sf_address_family_ipv4:
            ipv4_handler->af = AF_INET;
            ipv6_handler->af = AF_UNSPEC;
            break;
        case sf_address_family_ipv6:
            ipv4_handler->af = AF_UNSPEC;
            ipv6_handler->af = AF_INET6;
            break;
        case sf_address_family_both:
            ipv4_handler->af = AF_INET;
            ipv6_handler->af = AF_INET6;
            break;
        default:
            break;
    }

    return 0;
}

int sf_load_context_from_config_ex(SFContext *sf_context,
        SFContextIniConfig *config, const int fixed_buff_size,
        const int task_buffer_extra_size)
{
    SFAddressFamilyHandler *fh;
    SFNetworkHandler *sock_handler;
    SFNetworkHandler *rdma_handler;
    SFNetworkHandler *handler;
    SFNetworkHandler *end;
    char *inner_port_str;
    char *outer_port_str;
    int inner_port;
    int outer_port;
    int port;
    bool use_send_zc;
    int i;
    int result;

    inner_port_str = iniGetStrValue(config->ini_ctx.section_name,
            "inner_port", config->ini_ctx.context);
    outer_port_str = iniGetStrValue(config->ini_ctx.section_name,
            "outer_port", config->ini_ctx.context);
    if (inner_port_str == NULL && outer_port_str == NULL) {
        port = iniGetIntValue(config->ini_ctx.section_name,
                "port", config->ini_ctx.context, 0);
        if (port > 0) {
            inner_port = outer_port = port;
        } else {
            inner_port = outer_port = 0;
        }
    } else {
        if (inner_port_str != NULL) {
            inner_port = strtol(inner_port_str, NULL, 10);
        } else {
            inner_port = 0;
        }

        if (outer_port_str != NULL) {
            outer_port = strtol(outer_port_str, NULL, 10);
        } else {
            outer_port = 0;
        }
    }

    if (inner_port <= 0) {
        inner_port = config->default_inner_port;
    }
    if (outer_port <= 0) {
        outer_port = config->default_outer_port;
    }

    use_send_zc = iniGetBoolValue(config->ini_ctx.section_name,
                "use_send_zc", config->ini_ctx.context, false);
    for (i=0; i<SF_ADDRESS_FAMILY_COUNT; i++) {
        fh = sf_context->handlers + i;
        fh->ctx = sf_context;
        sock_handler = fh->handlers + SF_SOCKET_NETWORK_HANDLER_INDEX;
        rdma_handler = fh->handlers + SF_RDMACM_NETWORK_HANDLER_INDEX;
        sock_handler->comm_type = fc_comm_type_sock;
        rdma_handler->comm_type = fc_comm_type_rdma;
        if (config->comm_type == fc_comm_type_sock) {
            sock_handler->enabled = true;
            rdma_handler->enabled = false;
        } else if (config->comm_type == fc_comm_type_rdma) {
            sock_handler->enabled = false;
            rdma_handler->enabled = true;
        } else if (config->comm_type == fc_comm_type_both) {
            sock_handler->enabled = true;
            rdma_handler->enabled = true;
        }

        end = fh->handlers + SF_NETWORK_HANDLER_COUNT;
        for (handler=fh->handlers; handler<end; handler++) {
            if (!handler->enabled) {
                continue;
            }
            if ((result=init_network_handler(sf_context, handler,
                            fh, use_send_zc)) != 0)
            {
                return result;
            }
        }

        sock_handler->inner.port = inner_port;
        sock_handler->outer.port = outer_port;
        if (sock_handler->inner.port == sock_handler->outer.port) {
            sock_handler->inner.enabled = true;
            sock_handler->outer.enabled = false;
        } else {
            sock_handler->inner.enabled = true;
            sock_handler->outer.enabled = true;
        }

        rdma_handler->inner.port = sock_handler->inner.port;
        rdma_handler->inner.enabled = sock_handler->inner.enabled;
        rdma_handler->outer.port = sock_handler->outer.port;
        rdma_handler->outer.enabled = sock_handler->outer.enabled;

    }

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

    if ((result=load_bind_address(sf_context, config)) != 0) {
        return result;
    }

    if ((result=load_address_family(sf_context, config)) != 0) {
        return result;
    }

    if ((result=load_network_parameters(&config->ini_ctx, config->
                    max_pkg_size_item_name, config->max_pkg_size_min_value,
                    fixed_buff_size, task_buffer_extra_size,
                    &sf_context->net_buffer_cfg)) != 0)
    {
        return result;
    }

    return 0;
}

int sf_alloc_rdma_pd(SFContext *sf_context,
        FCAddressPtrArray *address_array)
{
    SFAddressFamilyHandler *fh;
    SFNetworkHandler *handler;
    int i;
    int result;

    for (i=0; i<SF_ADDRESS_FAMILY_COUNT; i++) {
        fh = sf_context->handlers + i;
        if (fh->af == AF_UNSPEC) {
            continue;
        }

        handler = fh->handlers + SF_RDMACM_NETWORK_HANDLER_INDEX;
        if (handler->enabled) {
            if ((handler->pd=fc_alloc_rdma_pd(handler->alloc_pd,
                            address_array, &result)) == NULL)
            {
                return result;
            }
        }
    }

    return 0;
}

void sf_set_address_family_by_ip(SFContext *sf_context,
        FCAddressPtrArray *address_array)
{
    SFAddressFamilyHandler *handler;
    SFAddressFamilyHandler *hend;
    FCAddressInfo **pp_addr;
    FCAddressInfo **addr_end;

    if (sf_context->address_family != sf_address_family_auto) {
        return;
    }

    hend = sf_context->handlers + SF_ADDRESS_FAMILY_COUNT;
    for (handler=sf_context->handlers; handler<hend; handler++) {
        if (handler->af == AF_UNSPEC) {
            continue;
        }

        if (*(handler->inner_bind_addr) == '\0' &&
                *(handler->outer_bind_addr) == '\0')
        {
            handler->af = AF_UNSPEC;
        }
    }

    addr_end = address_array->addrs + address_array->count;
    for (pp_addr=address_array->addrs; pp_addr<addr_end; pp_addr++) {
        if ((*pp_addr)->conn.af == AF_INET) {
            sf_context->handlers[SF_IPV4_ADDRESS_FAMILY_INDEX].af = AF_INET;
        } else {
            sf_context->handlers[SF_IPV6_ADDRESS_FAMILY_INDEX].af = AF_INET6;
        }
    }
}

static void combine_bind_addr(char *bind_addr, const char *ip_addr)
{
    char *p;

    if (*bind_addr == '\0') {
        p = bind_addr;
    } else {
        p = bind_addr + strlen(bind_addr);
        *p++ = ',';
    }
    strcpy(p, ip_addr);
}

static const char *get_address_family_caption(
        const SFAddressFamily address_family)
{
    switch (address_family) {
        case sf_address_family_auto:
            return "auto";
        case sf_address_family_ipv4:
            return "IPv4";
        case sf_address_family_ipv6:
            return "IPv6";
        case sf_address_family_both:
            return "both";
        default:
            return "unkown";
    }
}

void sf_context_config_to_string(const SFContext *sf_context,
        char *output, const int size)
{
    const SFAddressFamilyHandler *fh;
    const SFNetworkHandler *sock_handler;
    char inner_bind_addr[2 * IP_ADDRESS_SIZE + 2];
    char outer_bind_addr[2 * IP_ADDRESS_SIZE + 2];
    int i;
    int len;

    *inner_bind_addr = '\0';
    *outer_bind_addr = '\0';
    sock_handler = NULL;
    for (i=0; i<SF_ADDRESS_FAMILY_COUNT; i++) {
        fh = sf_context->handlers + i;
        if (fh->af == AF_UNSPEC) {
            continue;
        }

        if (*(fh->inner_bind_addr) != '\0') {
            combine_bind_addr(inner_bind_addr, fh->inner_bind_addr);
        }
        if (*(fh->outer_bind_addr) != '\0') {
            combine_bind_addr(outer_bind_addr, fh->outer_bind_addr);
        }

        sock_handler = fh->handlers + SF_SOCKET_NETWORK_HANDLER_INDEX;
    }

    len = 0;
    if ((sock_handler->inner.port == sock_handler->outer.port) &&
            (strcmp(inner_bind_addr, outer_bind_addr) == 0))
    {
        len += snprintf(output + len, size - len,
                "port=%u, bind_addr=%s",
                sock_handler->inner.port,
                inner_bind_addr);
    } else {
        len += snprintf(output + len, size - len,
                "inner_port=%u, inner_bind_addr=%s, "
                "outer_port=%u, outer_bind_addr=%s",
                sock_handler->inner.port, inner_bind_addr,
                sock_handler->outer.port, outer_bind_addr);
    }

    len += snprintf(output + len, size - len,
            ", address_family=%s, accept_threads=%d, work_threads=%d",
            get_address_family_caption(sf_context->address_family),
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

void sf_global_config_to_string_ex(const char *max_pkg_size_item_nm,
        char *output, const int size)
{
    int i;
    int len;
    int max_pkg_size;
    int min_buff_size;
    int max_buff_size;
#if IOEVENT_USE_URING
    bool use_io_uring;
    bool use_send_zc;
#endif
    char pkg_buff[256];
    SFAddressFamilyHandler *fh;
    SFNetworkHandler *handler;
    SFNetworkHandler *end;

    max_pkg_size = g_sf_global_vars.net_buffer_cfg.max_pkg_size -
        g_sf_global_vars.task_buffer_extra_size;
    min_buff_size = g_sf_global_vars.net_buffer_cfg.min_buff_size -
        g_sf_global_vars.task_buffer_extra_size;
    max_buff_size = g_sf_global_vars.net_buffer_cfg.max_buff_size -
        g_sf_global_vars.task_buffer_extra_size;

    if (min_buff_size == max_buff_size && max_pkg_size == max_buff_size) {
        snprintf(pkg_buff, sizeof(pkg_buff), "%s=%d KB",
                max_pkg_size_item_nm, max_pkg_size / 1024);
    } else {
        snprintf(pkg_buff, sizeof(pkg_buff), "%s=%d KB, "
                "min_buff_size=%d KB, max_buff_size=%d KB",
                max_pkg_size_item_nm, max_pkg_size / 1024,
                min_buff_size / 1024, max_buff_size / 1024);
    }

#if IOEVENT_USE_URING
    use_io_uring = false;
    use_send_zc = false;
    for (i=0; i<SF_ADDRESS_FAMILY_COUNT; i++) {
        fh = g_sf_context.handlers + i;
        end = fh->handlers + SF_NETWORK_HANDLER_COUNT;
        for (handler=fh->handlers; handler<end; handler++) {
            if (handler->enabled && handler->use_io_uring) {
                use_io_uring = true;
                use_send_zc = handler->use_send_zc;
                break;
            }
        }
    }
#endif

    len = snprintf(output, size,
            "base_path=%s, max_connections=%d, connect_timeout=%d, "
            "network_timeout=%d, thread_stack_size=%d KB, %s, ",
            SF_G_BASE_PATH_STR,
            g_sf_global_vars.net_buffer_cfg.max_connections,
            g_sf_global_vars.net_buffer_cfg.connect_timeout,
            g_sf_global_vars.net_buffer_cfg.network_timeout,
            g_sf_global_vars.thread_stack_size / 1024, pkg_buff);

#if IOEVENT_USE_URING
    len += snprintf(output + len, size - len,
            "use_io_uring=%d, use_send_zc=%d, ",
            use_io_uring, use_send_zc);
#endif

    len += snprintf(output + len, size - len,
            "tcp_quick_ack=%d, "
            "log_level=%s, "
            "run_by_group=%s, run_by_user=%s, ",
            g_sf_global_vars.tcp_quick_ack,
            log_get_level_caption(),
            g_sf_global_vars.run_by.group,
            g_sf_global_vars.run_by.user);

    sf_log_config_to_string(&g_sf_global_vars.error_log,
            "error-log", output + len, size - len);
}

void sf_log_config_ex(const char *other_config)
{
    char sz_global_config[512];
    char sz_context_config[128];

    sf_global_config_to_string(sz_global_config, sizeof(sz_global_config));

    if (!g_sf_context.is_client) {
        sf_context_config_to_string(&g_sf_context, sz_context_config,
                sizeof(sz_context_config));
    } else {
        *sz_context_config = '\0';
    }

    logInfo("%s%s%s%s%s", sz_global_config, (*sz_context_config != '\0') ?
            ", " : "", sz_context_config,
            (other_config != NULL && *other_config != '\0')  ? ", " : "",
            (other_config != NULL) ? other_config : ""
           );
}

int sf_load_data_path_config_ex(IniFullContext *ini_ctx,
        const char *item_name, const char *default_value, string_t *path)
{
    const char *data_path;
    int data_path_len;
    int path_size;

    data_path = iniGetStrValue(ini_ctx->section_name,
            item_name, ini_ctx->context);
    if (data_path == NULL) {
        data_path = default_value;
    } else if (*data_path == '\0') {
        logError("file: "__FILE__", line: %d, "
                "config file: %s%s%s, empty %s! "
                "please set %s correctly.", __LINE__,
                ini_ctx->filename, ini_ctx->section_name != NULL ?
                ", section: " : "", ini_ctx->section_name != NULL ?
                ini_ctx->section_name : "", item_name, item_name);
        return EINVAL;
    }

    data_path_len = strlen(data_path);
    if (*data_path == '/') {
        path->len = data_path_len;
        path->str = fc_strdup1(data_path, path->len);
        if (path->str == NULL) {
            return ENOMEM;
        }
    } else {
        path_size = SF_G_BASE_PATH_LEN + data_path_len + 2;
        path->str = (char *)fc_malloc(path_size);
        if (path->str == NULL) {
            return ENOMEM;
        }

        path->len = fc_get_full_filepath_ex(SF_G_BASE_PATH_STR,
                SF_G_BASE_PATH_LEN, data_path, data_path_len,
                path->str, path_size);
    }
    chopPath(path->str);
    path->len = strlen(path->str);

    if (access(path->str, F_OK) != 0) {
        if (errno != ENOENT) {
            logError("file: "__FILE__", line: %d, "
                    "access %s fail, errno: %d, error info: %s",
                    __LINE__, path->str, errno, STRERROR(errno));
            return errno != 0 ? errno : EPERM;
        }

        if (mkdir(path->str, 0775) != 0) {
            logError("file: "__FILE__", line: %d, "
                    "mkdir %s fail, errno: %d, error info: %s",
                    __LINE__, path->str, errno, STRERROR(errno));
            return errno != 0 ? errno : EPERM;
        }

        SF_CHOWN_TO_RUNBY_RETURN_ON_ERROR(path->str);
    }

    return 0;
}
