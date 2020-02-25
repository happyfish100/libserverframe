//sf_global.h

#ifndef _SF_GLOBAL_H
#define _SF_GLOBAL_H

#include "fastcommon/common_define.h"
#include "fastcommon/ini_file_reader.h"
#include "fastcommon/ioevent.h"
#include "sf_define.h"

typedef struct sf_connection_stat {
    volatile int current_count;
    volatile int max_count;
} SFConnectionStat;

typedef struct sf_custom_config {
    const char *item_prefix_name;
    int default_port;
} SFCustomConfig;

typedef struct sf_global_variables {
    int connect_timeout;
    int network_timeout;
    char base_path[MAX_PATH_SIZE];

    struct nio_thread_data *thread_data;

    volatile bool continue_flag;
    int outer_port;
    int inner_port;
    int max_connections;
    int accept_threads;
    int work_threads;
    int thread_stack_size;
    int max_pkg_size;
    int min_buff_size;
    int max_buff_size;
    int sync_log_buff_interval; //sync log buff to disk every interval seconds

    time_t up_time;

    gid_t run_by_gid;
    uid_t run_by_uid;
    char run_by_group[32];
    char run_by_user[32];

    bool rotate_error_log;
    int log_file_keep_days;

    char inner_bind_addr[IP_ADDRESS_SIZE];
    char outer_bind_addr[IP_ADDRESS_SIZE];

    SFConnectionStat connection_stat;
} SFGlobalVariables;

#ifdef __cplusplus
extern "C" {
#endif

extern SFGlobalVariables       g_sf_global_vars;

#define SF_G_BASE_PATH         g_sf_global_vars.base_path
#define SF_G_CONTINUE_FLAG     g_sf_global_vars.continue_flag
#define SF_G_CONNECT_TIMEOUT   g_sf_global_vars.connect_timeout
#define SF_G_NETWORK_TIMEOUT   g_sf_global_vars.network_timeout
#define SF_G_WORK_THREADS      g_sf_global_vars.work_threads
#define SF_G_THREAD_STACK_SIZE g_sf_global_vars.thread_stack_size

#define SF_SET_CUSTOM_CONFIG(cfg, prefix_name, port) \
    do { \
        (cfg).item_prefix_name = prefix_name;    \
        (cfg).default_port = port; \
    } while (0)

#define SF_CHOWN_RETURN_ON_ERROR(path, current_uid, current_gid) \
    do { \
    if (!(g_sf_global_vars.run_by_gid == current_gid && \
                g_sf_global_vars.run_by_uid == current_uid)) \
    { \
        if (chown(path, g_sf_global_vars.run_by_uid, \
                    g_sf_global_vars.run_by_gid) != 0) \
        { \
            logError("file: "__FILE__", line: %d, " \
                "chown \"%s\" fail, " \
                "errno: %d, error info: %s", \
                __LINE__, path, errno, STRERROR(errno)); \
            return errno != 0 ? errno : EPERM; \
        } \
    } \
    } while (0)

int sf_load_config(const char *server_name, const char *filename, 
        IniContext *pIniContext, const int default_inner_port,
        const int default_outer_port);

int sf_load_config_ex(const char *server_name, const char *filename,
        IniContext *pIniContext, const SFCustomConfig *inner_cfg,
        const SFCustomConfig *outer_cfg);

void sf_log_config_ex(const char *other_config);

#define sf_log_config() sf_log_config_ex(NULL)

#ifdef __cplusplus
}
#endif

#endif

