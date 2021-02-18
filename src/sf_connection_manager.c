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
#include <fcntl.h>
#include <errno.h>
#include "sf_global.h"
#include "sf_proto.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/fc_atomic.h"
#include "sf_connection_manager.h"

static ConnectionInfo *get_spec_connection(SFConnectionManager *cm,
        const ConnectionInfo *target, int *err_no)
{
    return conn_pool_get_connection(&cm->cpool, target, err_no);
}

static ConnectionInfo *make_connection(SFConnectionManager *cm,
        FCAddressPtrArray *addr_array, int *err_no)
{
    FCAddressInfo **current;
    FCAddressInfo **addr;
    FCAddressInfo **end;
    ConnectionInfo *conn;

    if (addr_array->count <= 0) {
        *err_no = ENOENT;
        return NULL;
    }

    current = addr_array->addrs + addr_array->index;
    if ((conn=get_spec_connection(cm, &(*current)->conn,
                    err_no)) != NULL)
    {
        return conn;
    }

    if (addr_array->count == 1) {
        return NULL;
    }

    end = addr_array->addrs + addr_array->count;
    for (addr=addr_array->addrs; addr<end; addr++) {
        if (addr == current) {
            continue;
        }

        if ((conn=get_spec_connection(cm, &(*addr)->conn,
                        err_no)) != NULL)
        {
            addr_array->index = addr - addr_array->addrs;
            return conn;
        }
    }

    return NULL;
}

static int validate_connection_callback(ConnectionInfo *conn, void *args)
{
    SFConnectionManager *cm;
    SFResponseInfo response;
    int result;

    cm = (SFConnectionManager *)args;
    if ((result=sf_active_test(conn, &response, cm->common_cfg->
                    network_timeout)) != 0)
    {
        sf_log_network_error(&response, conn, result);
    }

    return result;
}

static int init_group_array(SFCMConnGroupArray *garray, const int group_count,
        const int min_group_id)
{
    int result;
    int bytes;
    SFCMConnGroupEntry *group;
    SFCMConnGroupEntry *end;

    bytes = sizeof(SFCMConnGroupEntry) * group_count;
    garray->entries = (SFCMConnGroupEntry *)fc_malloc(bytes);
    if (garray->entries == NULL) {
        return ENOMEM;
    }
    memset(garray->entries, 0, bytes);

    end = garray->entries + group_count;
    for (group=garray->entries; group<end; group++) {
        if ((result=init_pthread_lock(&group->lock)) != 0) {
            return result;
        }
    }

    garray->count = group_count;
    garray->min_group_id = min_group_id;
    garray->max_group_id = min_group_id + group_count - 1;
    return 0;
}

int sf_connection_manager_init(SFConnectionManager *cm,
        const SFClientCommonConfig *common_cfg, const int group_count,
        const int min_group_id, const int server_group_index,
        const int server_count, const int max_count_per_entry,
        const int max_idle_time, fc_connection_callback_func
        connect_done_callback, void *args)
{
    const int socket_domain = AF_INET;
    int htable_init_capacity;
    int result;

    htable_init_capacity = 4 * server_count;
    if (htable_init_capacity < 256) {
        htable_init_capacity = 256;
    }
    if ((result=conn_pool_init_ex1(&cm->cpool, common_cfg->connect_timeout,
                    max_count_per_entry, max_idle_time, socket_domain,
                    htable_init_capacity, connect_done_callback, args,
                    validate_connection_callback, cm,
                    sizeof(SFConnectionParameters))) != 0)
    {
        return result;
    }

    if ((result=init_group_array(&cm->groups, group_count,
                    min_group_id)) != 0)
    {
        return result;
    }

    cm->server_group_index = server_group_index;
    cm->common_cfg = common_cfg;
    cm->max_servers_per_group = 0;
    return 0;
}

int sf_connection_manager_add(SFConnectionManager *cm, const int group_id,
        FCServerInfo **servers, const int count)
{
    SFCMConnGroupEntry *group;
    FCServerInfo **server;
    FCServerInfo **end;
    SFCMServerEntry *entry;

    if (group_id < cm->groups.min_group_id) {
        logError("file: "__FILE__", line: %d, "
                "invalid group id: %d which < min group id: %d",
                __LINE__, group_id, cm->groups.min_group_id);
        return EINVAL;
    }
    if (group_id > cm->groups.max_group_id) {
        logError("file: "__FILE__", line: %d, "
                "invalid group id: %d which > max group id: %d",
                __LINE__, group_id, cm->groups.max_group_id);
        return EINVAL;
    }

    group = cm->groups.entries + (group_id - cm->groups.min_group_id);
    group->id = group_id;
    group->all.servers = (SFCMServerEntry *)fc_malloc(
            sizeof(SFCMServerEntry) * count);
    if (group->all.servers == NULL) {
        return ENOMEM;
    }
    group->all.count = count;

    end = servers + count;
    for (entry=group->all.servers, server=servers;
            server<end; entry++, server++)
    {
        entry->id = (*server)->id;
        entry->addr_array = &(*server)->group_addrs[
            cm->server_group_index].address_array;
        entry->conn = NULL;
    }

    if (count > cm->max_servers_per_group) {
        cm->max_servers_per_group = count;
    }

    return 0;
}

static SFCMServerEntry *get_server_by_id(SFCMConnGroupEntry *group,
        const int server_id)
{
    SFCMServerEntry *server;
    SFCMServerEntry *end;

    end = group->all.servers + group->all.count;
    for (server=group->all.servers; server<end; server++) {
        if (server->id == server_id) {
            return server;
        }
    }

    return NULL;
}

static SFCMServerPtrArray *convert_to_sptr_array(SFConnectionManager *cm,
        SFCMConnGroupEntry *group, SFGroupServerArray *sarray, int *err_no)
{
    SFCMServerPtrArray *alives;
    SFGroupServerInfo *server;
    SFGroupServerInfo *end;
    SFCMServerEntry *sentry;

    if (sarray->count > cm->max_servers_per_group) {
        logError("file: "__FILE__", line: %d, "
                "group id: %d, response server count: %d > "
                "max count: %d!", __LINE__, group->id,
                sarray->count, cm->max_servers_per_group);
        *err_no = EOVERFLOW;
        return NULL;
    }

    alives = (SFCMServerPtrArray *)fast_mblock_alloc_object(
            &cm->sptr_array_allocator);
    if (alives == NULL) {
        *err_no = ENOMEM;
        return NULL;
    }

    alives->count = 0;
    end = sarray->servers + sarray->count;
    for (server=sarray->servers; server<end; server++) {
        if ((sentry=get_server_by_id(group, server->id)) == NULL) {
            logError("file: "__FILE__", line: %d, "
                    "group id: %d, response server count: %d > "
                    "max count: %d!", __LINE__, group->id,
                    sarray->count, cm->max_servers_per_group);
            *err_no = ENOENT;
            fast_mblock_free_object(&cm->sptr_array_allocator, alives);
            return NULL;
        }

        if (server->is_master) {
            FC_ATOMIC_SET(group->master, sentry);
            if (cm->common_cfg->read_rule != sf_data_read_rule_slave_first) {
                alives->servers[alives->count++] = sentry;
            }
        } else if (server->is_active) {
            alives->servers[alives->count++] = sentry;
        }
    }

    *err_no = 0;
    return alives;
}

static int sptr_array_compare(SFCMServerPtrArray *a1,
        SFCMServerPtrArray *a2)
{
    int sub;
    int i;

    if ((sub=(a1->count - a2->count)) != 0) {
        return sub;
    }

    for (i = 0; i < a1->count; i++) {
        if ((sub=(a1->servers[i]->id - a2->servers[i]->id)) != 0) {
            return sub;
        }
    }

    return 0;
}

static int do_get_group_servers(SFConnectionManager *cm,
        SFCMConnGroupEntry *group, ConnectionInfo *conn)
{
#define MAX_GROUP_SERVER_COUNT 128
    int result;
    SFGroupServerInfo fixed_servers[MAX_GROUP_SERVER_COUNT];
    SFGroupServerArray sarray;
    SFCMServerPtrArray *old_alives;
    SFCMServerPtrArray *new_alives;

    sarray.alloc = MAX_GROUP_SERVER_COUNT;
    sarray.count = 0;
    sarray.servers = fixed_servers;
    if ((result=sf_proto_get_group_servers(conn, cm->common_cfg->
                    network_timeout, group->id, &sarray)) != 0)
    {
        return result;
    }

    if ((new_alives=convert_to_sptr_array(cm, group,
                    &sarray, &result)) == NULL)
    {
        return result;
    }
    old_alives = (SFCMServerPtrArray *)FC_ATOMIC_GET(group->alives);
    if (sptr_array_compare(old_alives, new_alives) == 0) {
        fast_mblock_free_object(&cm->sptr_array_allocator, new_alives);
        return 0;
    }

    if (__sync_bool_compare_and_swap(&group->alives,
                old_alives, new_alives))
    {
        fast_mblock_delay_free_object(&cm->sptr_array_allocator, old_alives,
                (cm->common_cfg->connect_timeout + cm->common_cfg->
                 network_timeout) * group->all.count);
    } else {
        fast_mblock_free_object(&cm->sptr_array_allocator, new_alives);
    }

    return 0;
}

static int get_group_servers_by_active(SFConnectionManager *cm,
        SFCMConnGroupEntry *group)
{
    SFCMServerPtrArray *alives;
    SFCMServerEntry **server;
    SFCMServerEntry **end;
    ConnectionInfo *conn;
    int result;

    result = ENOENT;
    alives = (SFCMServerPtrArray *)FC_ATOMIC_GET(group->alives);
    if (alives->count == 0) {
        return result;
    }

    end = alives->servers + alives->count;
    for (server=alives->servers; server<end; server++) {
        if ((conn=make_connection(cm, (*server)->addr_array,
                        &result)) == NULL)
        {
            continue;
        }

        result = do_get_group_servers(cm, group, conn);
        conn_pool_close_connection_ex(&cm->cpool, conn, result != 0);
        if (result == 0) {
            return 0;
        }
    }

    return result;
}

static int get_group_servers_by_all(SFConnectionManager *cm,
        SFCMConnGroupEntry *group)
{
    SFCMServerEntry *server;
    SFCMServerEntry *end;
    ConnectionInfo *conn;
    int result;

    result = ENOENT;
    if (group->all.count == 0) {
        return result;
    }

    end = group->all.servers + group->all.count;
    for (server=group->all.servers; server<end; server++) {
        if ((conn=make_connection(cm, server->addr_array,
                        &result)) == NULL)
        {
            continue;
        }

        result = do_get_group_servers(cm, group, conn);
        conn_pool_close_connection_ex(&cm->cpool, conn, result != 0);
        if (result == 0) {
            return 0;
        }
    }

    return result;
}

static int get_group_servers(SFConnectionManager *cm,
        SFCMConnGroupEntry *group)
{
    int result;

    if ((result=get_group_servers_by_active(cm, group)) == 0) {
        return 0;
    }

    return get_group_servers_by_all(cm, group);
}

static void *connection_manager_thread_func(void *arg)
{
    SFConnectionManager *cm;

    cm = (SFConnectionManager *)arg;
    while (1) {
        //TODO
    }

    return NULL;
}

static int sptr_array_alloc_init(void *element, void *args)
{
    SFCMServerPtrArray *sptr_array;

    sptr_array = (SFCMServerPtrArray *)element;
    sptr_array->servers = (SFCMServerEntry **)(sptr_array + 1);
    return 0;
}

int sf_connection_manager_start(SFConnectionManager *cm)
{
    pthread_t tid;
    int result;
    int element_size;
    SFCMConnGroupEntry *group;
    SFCMConnGroupEntry *end;
    SFCMServerPtrArray *sptr_array;

    element_size = sizeof(SFCMServerPtrArray) +
        sizeof(SFCMServerEntry *) * cm->max_servers_per_group;
    if ((result=fast_mblock_init_ex1(&cm->sptr_array_allocator,
                    "server_ptr_array", element_size, 4 * 1024, 0,
                    sptr_array_alloc_init, NULL, true)) != 0)
    {
        return result;
    }

    end = cm->groups.entries + cm->groups.count;
    for (group=cm->groups.entries; group<end; group++) {
        if (group->all.count == 0) {
            logError("file: "__FILE__", line: %d, "
                    "group id: %d, no servers!",
                    __LINE__, group->id);
            return ENOENT;
        }

        sptr_array = (SFCMServerPtrArray *)fast_mblock_alloc_object(
                &cm->sptr_array_allocator);
        if (sptr_array == NULL) {
            return ENOMEM;
        }
        __sync_bool_compare_and_swap(&group->alives, NULL, sptr_array);
    }

    return fc_create_thread(&tid, connection_manager_thread_func,
            cm, SF_G_THREAD_STACK_SIZE);
}
