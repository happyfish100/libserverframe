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

//sf_connection_manager.h

#ifndef _SF_CONNECTION_MANAGER_H
#define _SF_CONNECTION_MANAGER_H

#include "fastcommon/server_id_func.h"
#include "fastcommon/connection_pool.h"
#include "sf_types.h"

struct sf_connection_manager;

typedef ConnectionInfo *(*sf_get_connection_func)(
        struct sf_connection_manager *cm,
        const int group_index, int *err_no);

typedef ConnectionInfo *(*sf_get_server_connection_func)(
        struct sf_connection_manager *cm,
        FCServerInfo *server, int *err_no);

typedef ConnectionInfo *(*sf_get_spec_connection_func)(
        struct sf_connection_manager *cm,
        const ConnectionInfo *target, int *err_no);

typedef void (*sf_release_connection_func)(
        struct sf_connection_manager *cm, ConnectionInfo *conn);
typedef void (*sf_close_connection_func)(
        struct sf_connection_manager *cm, ConnectionInfo *conn);

typedef const struct sf_connection_parameters * (*sf_get_connection_parameters)(
        struct sf_connection_manager *cm, ConnectionInfo *conn);

typedef struct sf_cm_server_entry {
    int id;
    int group_index;
    FCAddressPtrArray *addr_array;
} SFCMServerEntry;

typedef struct sf_cm_server_array {
    SFCMServerEntry *servers;
    int count;
} SFCMServerArray;

typedef struct sf_cm_server_ptr_array {
    SFCMServerEntry **servers;
    int count;
} SFCMServerPtrArray;

typedef struct sf_cm_conn_group_entry {
    int id;
    SFCMServerArray all;
    volatile SFCMServerEntry *master;
    volatile SFCMServerPtrArray *alives;
    pthread_mutex_t lock;
} SFCMConnGroupEntry;

typedef struct sf_cm_conn_group_array {
    SFCMConnGroupEntry *entries;
    int count;
} SFCMConnGroupArray;

typedef struct sf_cm_operations {
    /* get the specify connection by ip and port */
    sf_get_spec_connection_func get_spec_connection;

    /* get one connection of the configured servers by data group */
    sf_get_connection_func get_connection;

    /* get one connection of the server */
    sf_get_server_connection_func get_server_connection;

    /* get the master connection from the server */
    sf_get_connection_func get_master_connection;

    /* get one readable connection from the server */
    sf_get_connection_func get_readable_connection;

    /* get the leader connection from the server */
    sf_get_server_connection_func get_leader_connection;

    /* push back to connection pool when use connection pool */
    sf_release_connection_func release_connection;

     /* disconnect the connecton on network error */
    sf_close_connection_func close_connection;

    sf_get_connection_parameters get_connection_params;
} SFCMOperations;

typedef struct sf_connection_manager {
    int server_group_index;
    int max_servers_per_group;
    const SFClientCommonConfig *common_cfg;
    SFCMConnGroupArray groups;
    ConnectionPool cpool;
    struct fast_mblock_man sptr_array_allocator; //element: SFCMServerPtrArray
    SFCMOperations ops;
} SFConnectionManager;

int sf_connection_manager_init(SFConnectionManager *cm,
        const SFClientCommonConfig *common_cfg, const int group_count,
        const int server_group_index, const int server_count,
        const int max_count_per_entry, const int max_idle_time,
        fc_connection_callback_func connect_done_callback, void *args);

int sf_connection_manager_add(SFConnectionManager *cm, const int group_id,
        FCServerInfo **servers, const int count);

int sf_connection_manager_start(SFConnectionManager *cm);

ConnectionInfo *sf_connection_manager_get_master(SFConnectionManager *cm,
        const int group_index, int *err_no);

ConnectionInfo *sf_connection_manager_get_readable(SFConnectionManager *cm,
        const int group_index, int *err_no);

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif
