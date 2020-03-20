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
    char base_path[MAX_PATH_SIZE];

    volatile bool continue_flag;
    int max_connections;
    int max_pkg_size;
    int min_buff_size;
    int max_buff_size;
    int thread_stack_size;
    int sync_log_buff_interval; //sync log buff to disk every interval seconds

    time_t up_time;
    gid_t run_by_gid;
    uid_t run_by_uid;
    char run_by_group[32];
    char run_by_user[32];

    bool rotate_error_log;
    int log_file_keep_days;

    SFConnectionStat connection_stat;
} SFGlobalVariables;

#ifdef __cplusplus
extern "C" {
#endif

extern SFGlobalVariables         g_sf_global_vars;
extern SFContext                 g_sf_context;

#define SF_G_BASE_PATH           g_sf_global_vars.base_path
#define SF_G_CONTINUE_FLAG       g_sf_global_vars.continue_flag
#define SF_G_CONNECT_TIMEOUT     g_sf_global_vars.connect_timeout
#define SF_G_NETWORK_TIMEOUT     g_sf_global_vars.network_timeout
#define SF_G_THREAD_STACK_SIZE   g_sf_global_vars.thread_stack_size
#define SF_G_WORK_THREADS        g_sf_context.work_threads
#define SF_G_ALIVE_THREAD_COUNT  g_sf_context.thread_count
#define SF_G_THREAD_INDEX(tdata) (int)(tdata - g_sf_context.thread_data)
#define SF_G_CONN_CURRENT_COUNT  g_sf_global_vars.connection_stat.current_count
#define SF_G_CONN_MAX_COUNT      g_sf_global_vars.connection_stat.max_count

#define SF_WORK_THREADS(sf_context)        sf_context.work_threads
#define SF_ALIVE_THREAD_COUNT(sf_context)  sf_context.thread_count
#define SF_THREAD_INDEX(sf_context, tdata) (int)(tdata - sf_context.thread_data)

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
        IniContext *pIniContext, const char *section_name,
        const int default_inner_port, const int default_outer_port);

int sf_load_context_from_config(SFContext *sf_context,
        const char *filename, IniContext *pIniContext,
        const char *section_name, const int default_inner_port,
        const int default_outer_port);

void sf_global_config_to_string(char *output, const int size);

void sf_context_config_to_string(const SFContext *sf_context,
        char *output, const int size);

void sf_log_config_ex(const char *other_config);

#define sf_log_config() sf_log_config_ex(NULL)

#ifdef __cplusplus
}
#endif

#endif

