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
#include "sf_types.h"
#include "sf_configs.h"

typedef struct sf_cm_server_entry {
    int server_id;
    ConnectionInfo *conn;
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
    SFCMServerEntry *master;
    SFCMServerArray all;
    SFCMServerPtrArray alives;
    pthread_mutex_t lock;
} SFCMConnGroupEntry;

typedef struct sf_cm_conn_group_array {
    SFCMConnGroupEntry *entries;
    int count;
    int min_group_id;
    int max_group_id;
} SFCMConnGroupArray;

typedef struct sf_connection_manager {
    int server_group_index;
    SFDataReadRule read_rule;  //the rule for read
    SFCMConnGroupArray groups;
} SFConnectionManager;

int sf_connection_manager_init(SFConnectionManager *cm, const int group_count,
        const int min_group_id, const int server_group_index,
        const SFDataReadRule read_rule);

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
