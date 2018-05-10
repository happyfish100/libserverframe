//sf_global.h

#ifndef _SF_GLOBAL_H
#define _SF_GLOBAL_H

#include "common_define.h"
#include "ini_file_reader.h"
#include "ioevent.h"

typedef struct sf_connection_stat {
    volatile int current_count;
    volatile int max_count;
} SFConnectionStat;

#ifdef __cplusplus
extern "C" {
#endif

extern int g_sf_connect_timeout;
extern int g_sf_network_timeout;
extern char g_sf_base_path[MAX_PATH_SIZE];

extern struct nio_thread_data *g_thread_data;

extern volatile bool g_continue_flag;
extern int g_outer_port;
extern int g_inner_port;
extern int g_max_connections;
extern int g_accept_threads;
extern int g_work_threads;
extern int g_thread_stack_size;
extern int g_max_pkg_size;
extern int g_min_buff_size;
extern int g_max_buff_size;
extern int g_sync_log_buff_interval; //sync log buff to disk every interval seconds

extern time_t g_up_time;

extern gid_t g_run_by_gid;
extern uid_t g_run_by_uid;
extern char g_run_by_group[32];
extern char g_run_by_user[32];

extern bool g_rotate_error_log;
extern int g_log_file_keep_days;

extern char g_inner_bind_addr[IP_ADDRESS_SIZE];
extern char g_outer_bind_addr[IP_ADDRESS_SIZE];

extern SFConnectionStat g_connection_stat;

int sf_load_config(const char *server_name, const char *filename, 
        IniContext *pIniContext, const int default_inner_port,
        const int default_outer_port);

#ifdef __cplusplus
}
#endif

#endif

