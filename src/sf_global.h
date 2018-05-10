//sf_global.h

#ifndef _SF_GLOBAL_H
#define _SF_GLOBAL_H

#include "fastcommon/common_define.h"
#include "fastcommon/ini_file_reader.h"
#include "fastcommon/ioevent.h"

typedef struct sf_connection_stat {
    volatile int current_count;
    volatile int max_count;
} SFConnectionStat;

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

extern SFGlobalVariables g_sf_global_vars;

int sf_load_config(const char *server_name, const char *filename, 
        IniContext *pIniContext, const int default_inner_port,
        const int default_outer_port);

void sf_log_config();

#ifdef __cplusplus
}
#endif

#endif

