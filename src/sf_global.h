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

//sf_global.h

#ifndef _SF_GLOBAL_H
#define _SF_GLOBAL_H

#include "fastcommon/common_define.h"
#include "fastcommon/ini_file_reader.h"
#include "fastcommon/ioevent.h"
#include "sf_define.h"
#include "sf_types.h"

typedef struct sf_connection_stat {
    volatile int current_count;
    volatile int max_count;
} SFConnectionStat;

typedef struct sf_global_variables {
    int connect_timeout;
    int network_timeout;
    struct {
        char str[MAX_PATH_SIZE];
        bool inited;
        bool created;
    } base_path;

    volatile bool continue_flag;
    bool tcp_quick_ack;
    bool epoll_edge_trigger;
    int max_connections;
    int max_pkg_size;
    int min_buff_size;
    int max_buff_size;
    int task_buffer_extra_size;
    int thread_stack_size;

    time_t up_time;
    struct {
        bool inited;
        gid_t gid;
        uid_t uid;
        char group[32];
        char user[32];
    } run_by;

    SFLogConfig error_log;
    SFConnectionStat connection_stat;
    sf_error_handler_callback error_handler;
    string_t empty;
    volatile time_t last_binlog_writer_log_timestamp;
} SFGlobalVariables;

typedef struct sf_context_ini_config {
    IniFullContext ini_ctx;
    int default_inner_port;
    int default_outer_port;
    int default_work_threads;
    FCCommunicationType comm_type;
    const char *max_pkg_size_item_name;
} SFContextIniConfig;

#ifdef __cplusplus
extern "C" {
#endif

extern SFGlobalVariables         g_sf_global_vars;
extern SFContext                 g_sf_context;

#define SF_G_BASE_PATH_STR       g_sf_global_vars.base_path.str
#define SF_G_BASE_PATH_INITED    g_sf_global_vars.base_path.inited
#define SF_G_BASE_PATH_CREATED   g_sf_global_vars.base_path.created
#define SF_G_CONTINUE_FLAG       g_sf_global_vars.continue_flag
#define SF_G_CONNECT_TIMEOUT     g_sf_global_vars.connect_timeout
#define SF_G_NETWORK_TIMEOUT     g_sf_global_vars.network_timeout
#define SF_G_MAX_CONNECTIONS     g_sf_global_vars.max_connections
#define SF_G_THREAD_STACK_SIZE   g_sf_global_vars.thread_stack_size
#define SF_G_UP_TIME             g_sf_global_vars.up_time

#define SF_G_SOCK_HANDLER        (g_sf_context.handlers  \
        [SF_IPV4_ADDRESS_FAMILY_INDEX].handlers + \
        SF_SOCKET_NETWORK_HANDLER_INDEX)
#define SF_G_OUTER_PORT          SF_G_SOCK_HANDLER->outer.port
#define SF_G_INNER_PORT          SF_G_SOCK_HANDLER->inner.port
#define SF_G_OUTER_BIND_ADDR4     g_sf_context.handlers  \
        [SF_IPV4_ADDRESS_FAMILY_INDEX].outer_bind_addr
#define SF_G_INNER_BIND_ADDR4     g_sf_context.handlers  \
        [SF_IPV4_ADDRESS_FAMILY_INDEX].inner_bind_addr
#define SF_G_OUTER_BIND_ADDR6     g_sf_context.handlers  \
        [SF_IPV6_ADDRESS_FAMILY_INDEX].outer_bind_addr
#define SF_G_INNER_BIND_ADDR6     g_sf_context.handlers  \
        [SF_IPV6_ADDRESS_FAMILY_INDEX].inner_bind_addr

#define SF_G_IPV4_ENABLED     (g_sf_context.handlers  \
        [SF_IPV4_ADDRESS_FAMILY_INDEX].af == AF_INET)
#define SF_G_IPV6_ENABLED     (g_sf_context.handlers  \
        [SF_IPV6_ADDRESS_FAMILY_INDEX].af == AF_INET6)

#define SF_G_ACCEPT_THREADS      g_sf_context.accept_threads
#define SF_G_WORK_THREADS        g_sf_context.work_threads
#define SF_G_ALIVE_THREAD_COUNT  g_sf_context.thread_count
#define SF_G_THREAD_INDEX(tdata) (int)(tdata - g_sf_context.thread_data)
#define SF_G_CONN_CURRENT_COUNT  g_sf_global_vars.connection_stat.current_count
#define SF_G_CONN_MAX_COUNT      g_sf_global_vars.connection_stat.max_count

#define SF_G_ERROR_HANDLER       g_sf_global_vars.error_handler
#define SF_G_EMPTY_STRING        g_sf_global_vars.empty
#define LAST_BINLOG_WRITER_LOG_TIMESTAMP  g_sf_global_vars. \
    last_binlog_writer_log_timestamp

#define SF_G_EPOLL_EDGE_TRIGGER  g_sf_global_vars.epoll_edge_trigger

#define SF_WORK_THREADS(sf_context)        (sf_context).work_threads
#define SF_ALIVE_THREAD_COUNT(sf_context)  (sf_context).thread_count
#define SF_THREAD_INDEX(sf_context, tdata) (int)(tdata - (sf_context).thread_data)

#define SF_IPV4_ENABLED(sf_context)   ((sf_context).handlers  \
        [SF_IPV4_ADDRESS_FAMILY_INDEX].af == AF_INET)
#define SF_IPV6_ENABLED(sf_context)   ((sf_context).handlers  \
        [SF_IPV6_ADDRESS_FAMILY_INDEX].af == AF_INET6)

#define SF_CHOWN_RETURN_ON_ERROR(path, current_uid, current_gid) \
    do { \
        if (g_sf_global_vars.run_by.inited && !(g_sf_global_vars.  \
                    run_by.gid == current_gid && g_sf_global_vars. \
                    run_by.uid == current_uid)) \
        { \
            if (chown(path, g_sf_global_vars.run_by.uid, \
                        g_sf_global_vars.run_by.gid) != 0) \
            { \
                logError("file: "__FILE__", line: %d, " \
                        "chown \"%s\" fail, " \
                        "errno: %d, error info: %s", \
                        __LINE__, path, errno, STRERROR(errno)); \
                return errno != 0 ? errno : EPERM; \
            } \
        } \
    } while (0)

#define SF_CHOWN_TO_RUNBY_RETURN_ON_ERROR(path) \
    SF_CHOWN_RETURN_ON_ERROR(path, geteuid(), getegid())


#define SF_FCHOWN_RETURN_ON_ERROR(fd, path, current_uid, current_gid) \
    do { \
        if (g_sf_global_vars.run_by.inited && !(g_sf_global_vars.  \
                    run_by.gid == current_gid && g_sf_global_vars. \
                    run_by.uid == current_uid)) \
        { \
            if (fchown(fd, g_sf_global_vars.run_by.uid, \
                        g_sf_global_vars.run_by.gid) != 0) \
            { \
                logError("file: "__FILE__", line: %d, " \
                        "fchown \"%s\" fail, " \
                        "errno: %d, error info: %s", \
                        __LINE__, path, errno, STRERROR(errno)); \
                return errno != 0 ? errno : EPERM; \
            } \
        } \
    } while (0)

#define SF_FCHOWN_TO_RUNBY_RETURN_ON_ERROR(fd, path) \
    SF_FCHOWN_RETURN_ON_ERROR(fd, path, geteuid(), getegid())

#define SF_SET_CONTEXT_INI_CONFIG_EX(config, the_comm_type, filename,   \
        pIniContext, section_name, def_inner_port, def_outer_port, \
        def_work_threads, max_pkg_size_item_nm) \
    do { \
        FAST_INI_SET_FULL_CTX_EX(config.ini_ctx, filename, \
                section_name, pIniContext);   \
        config.comm_type = the_comm_type; \
        config.default_inner_port = def_inner_port; \
        config.default_outer_port = def_outer_port; \
        config.default_work_threads = def_work_threads; \
        config.max_pkg_size_item_name = max_pkg_size_item_nm; \
    } while (0)

#define SF_SET_CONTEXT_INI_CONFIG(config, the_comm_type,     \
        filename, pIniContext, section_name, def_inner_port, \
        def_outer_port, def_work_threads) \
     SF_SET_CONTEXT_INI_CONFIG_EX(config, the_comm_type, filename, \
             pIniContext, section_name, def_inner_port, def_outer_port, \
             def_work_threads, "max_pkg_size")

int sf_load_global_config_ex(const char *log_filename_prefix,
        IniFullContext *ini_ctx, const bool load_network_params,
        const char *max_pkg_size_item_nm, const int fixed_buff_size,
        const int task_buffer_extra_size, const bool need_set_run_by);

static inline int sf_load_global_config(const char *log_filename_prefix,
        IniFullContext *ini_ctx)
{
    const bool load_network_params = true;
    const char *max_pkg_size_item_nm = "max_pkg_size";
    const int fixed_buff_size = 0;
    const int task_buffer_extra_size = 0;
    const bool need_set_run_by = true;

    return sf_load_global_config_ex(log_filename_prefix, ini_ctx,
            load_network_params, max_pkg_size_item_nm, fixed_buff_size,
            task_buffer_extra_size, need_set_run_by);
}

int sf_load_config_ex(const char *log_filename_prefix,
        SFContextIniConfig *config, const int fixed_buff_size,
        const int task_buffer_extra_size, const bool need_set_run_by);

static inline int sf_load_config(const char *log_filename_prefix,
        const FCCommunicationType comm_type,
        const char *filename, IniContext *pIniContext,
        const char *section_name, const int default_inner_port,
        const int default_outer_port, const int fixed_buff_size,
        const int task_buffer_extra_size)
{
    const bool need_set_run_by = true;
    SFContextIniConfig config;

    SF_SET_CONTEXT_INI_CONFIG(config, comm_type, filename, pIniContext,
            section_name, default_inner_port, default_outer_port,
            DEFAULT_WORK_THREADS);
    return sf_load_config_ex(log_filename_prefix, &config, fixed_buff_size,
            task_buffer_extra_size, need_set_run_by);
}

int sf_load_context_from_config_ex(SFContext *sf_context,
        SFContextIniConfig *config);

static inline int sf_load_context_from_config(SFContext *sf_context,
        const FCCommunicationType comm_type,
        const char *filename, IniContext *pIniContext,
        const char *section_name, const int default_inner_port,
        const int default_outer_port)
{
    SFContextIniConfig config;

    SF_SET_CONTEXT_INI_CONFIG(config, comm_type, filename, pIniContext,
            section_name, default_inner_port, default_outer_port,
            DEFAULT_WORK_THREADS);
    return sf_load_context_from_config_ex(sf_context, &config);
}

int sf_alloc_rdma_pd(SFContext *sf_context,
        FCAddressPtrArray *address_array);

void sf_set_address_family_by_ip(SFContext *sf_context,
        FCAddressPtrArray *address_array);

int sf_load_log_config(IniFullContext *ini_ctx, LogContext *log_ctx,
        SFLogConfig *log_cfg);

int sf_load_slow_log_config_ex(IniFullContext *ini_ctx, LogContext *log_ctx,
        SFSlowLogConfig *slow_log_cfg);

static inline int sf_load_slow_log_config(const char *config_file,
        IniContext *ini_context, LogContext *log_ctx,
        SFSlowLogConfig *slow_log_cfg)
{
    IniFullContext ini_ctx;

    FAST_INI_SET_FULL_CTX_EX(ini_ctx, config_file, "slow-log", ini_context);
    return sf_load_slow_log_config_ex(&ini_ctx, log_ctx, slow_log_cfg);
}

void sf_set_log_rotate_size(LogContext *context, const int64_t log_rotate_size);

void sf_log_config_to_string_ex(SFLogConfig *log_cfg, const char *caption,
        const char *other_config, char *output, const int size);

void sf_slow_log_config_to_string(SFSlowLogConfig *slow_log_cfg,
        const char *caption, char *output, const int size);

void sf_global_config_to_string_ex(const char *max_pkg_size_item_nm,
        char *output, const int size);

static inline void sf_global_config_to_string(char *output, const int size)
{
    const char *max_pkg_size_item_nm = "max_pkg_size";
    sf_global_config_to_string_ex(max_pkg_size_item_nm, output, size);
}

void sf_context_config_to_string(const SFContext *sf_context,
        char *output, const int size);

void sf_log_config_ex(const char *other_config);

#define sf_log_config() sf_log_config_ex(NULL)

#define sf_log_config_to_string(log_cfg, caption, output, size)  \
    sf_log_config_to_string_ex(log_cfg, caption, NULL, output, size)

int sf_get_base_path_from_conf_file(const char *config_filename);
int sf_load_global_base_path(IniFullContext *ini_ctx);

int sf_load_data_path_config_ex(IniFullContext *ini_ctx,
        const char *item_name, const char *default_value, string_t *path);

#define sf_load_data_path_config(ini_ctx, path) \
    sf_load_data_path_config_ex(ini_ctx, "data_path", "data", path)

static inline void sf_set_global_base_path(const char *base_path)
{
    string_t path_string;

    FC_SET_STRING(path_string, (char *)base_path);
    normalize_path(NULL, &path_string, SF_G_BASE_PATH_STR,
            sizeof(SF_G_BASE_PATH_STR));
    SF_G_BASE_PATH_INITED = true;
}

static inline void sf_set_error_handler(
        sf_error_handler_callback error_handler)
{
    SF_G_ERROR_HANDLER = error_handler;
}

#ifdef __cplusplus
}
#endif

#endif
