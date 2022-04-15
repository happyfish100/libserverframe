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
#include "sf_configs.h"
#include "sf_proto.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/fc_atomic.h"
#include "sf_connection_manager.h"

static int get_group_servers(SFConnectionManager *cm,
        SFCMConnGroupEntry *group);

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

static ConnectionInfo *get_server_connection(SFConnectionManager *cm,
        FCServerInfo *server, int *err_no)
{
    FCAddressPtrArray *addr_array;
    ConnectionInfo *conn;

    addr_array = &server->group_addrs[cm->server_group_index].address_array;
    if ((conn=make_connection(cm, addr_array, err_no)) == NULL) {
        logError("file: "__FILE__", line: %d, "
                "server id: %d, get_server_connection fail",
                __LINE__, server->id);
    }
    return conn;
}

static ConnectionInfo *get_connection(SFConnectionManager *cm,
        const int group_index, int *err_no)
{
    SFCMServerArray *server_array;
    ConnectionInfo *conn;
    uint32_t server_hash_code;
    int server_index;
    int i;

    server_array = &cm->groups.entries[group_index].all;
    server_hash_code = rand();
    server_index = server_hash_code % server_array->count;
    if ((conn=make_connection(cm, server_array->servers[server_index].
                    addr_array, err_no)) != NULL)
    {
        return conn;
    }

    if (server_array->count > 1) {
        for (i=0; i<server_array->count; i++) {
            if (i == server_index) {
                continue;
            }

            if ((conn=make_connection(cm, server_array->servers[i].
                            addr_array, err_no)) != NULL)
            {
                return conn;
            }
        }
    }

    logError("file: "__FILE__", line: %d, "
            "data group index: %d, get_connection fail, "
            "configured server count: %d", __LINE__,
            group_index, server_array->count);
    return NULL;
}

static inline void set_connection_params(ConnectionInfo *conn,
        SFCMServerEntry *server, SFCMServerPtrArray *old_alives)
{
    SFConnectionParameters *cparam;
    cparam = (SFConnectionParameters *)conn->args;
    cparam->cm.sentry = server;
    cparam->cm.old_alives = old_alives;
}

static inline int push_to_detect_queue(SFConnectionManager *cm,
        SFCMConnGroupEntry *group, SFCMServerPtrArray *alives)
{
    if (!cm->alive_detect.bg_thread_enabled) {
        return 0;
    }

    if (alives->count < group->all.count) {
        if (__sync_bool_compare_and_swap(&group->in_queue, 0, 1)) {
            return common_blocked_queue_push(&cm->alive_detect.queue, group);
        }
    }

    return 0;
}

static inline bool alive_array_cas(SFConnectionManager *cm,
        SFCMConnGroupEntry *group, SFCMServerPtrArray *old_alives,
        SFCMServerPtrArray *new_alives)
{
    if (__sync_bool_compare_and_swap(&group->alives,
                old_alives, new_alives))
    {
        logDebug("file: "__FILE__", line: %d, "
                "[%s] group_id: %d, old alive server count: %d, "
                "new alive server count: %d", __LINE__, cm->module_name,
                group->id, old_alives->count, new_alives->count);

        push_to_detect_queue(cm, group, new_alives);
        fast_mblock_delay_free_object(&cm->sptr_array_allocator, old_alives,
                (cm->common_cfg->connect_timeout + cm->common_cfg->
                 network_timeout) * group->all.count);
        return true;
    } else {
        fast_mblock_free_object(&cm->sptr_array_allocator, new_alives);
        return false;
    }
}

static int remove_from_alives(SFConnectionManager *cm,
        SFCMConnGroupEntry *group, SFCMServerPtrArray *old_alives,
        SFCMServerEntry *server)
{
    SFCMServerPtrArray *new_alives;
    SFCMServerEntry **pp;
    SFCMServerEntry **dest;
    SFCMServerEntry **end;

    new_alives = (SFCMServerPtrArray *)FC_ATOMIC_GET(group->alives);
    if (new_alives != old_alives) {
        return 0;
    }

    new_alives = (SFCMServerPtrArray *)fast_mblock_alloc_object(
            &cm->sptr_array_allocator);
    if (new_alives == NULL) {
        return ENOMEM;
    }

    dest = new_alives->servers;
    end = old_alives->servers + old_alives->count;
    for (pp=old_alives->servers; pp<end; pp++) {
        if (*pp != server) {
            *dest++ = *pp;
        }
    }

    new_alives->count = dest - new_alives->servers;
    if (alive_array_cas(cm, group, old_alives, new_alives)) {
        SFCMServerEntry *master;
        master = (SFCMServerEntry *)FC_ATOMIC_GET(group->master);
        if (master == server) {
            __sync_bool_compare_and_swap(&group->master, master, NULL);
        }
    }

    return 0;
}

static inline ConnectionInfo *make_master_connection(SFConnectionManager *cm,
        SFCMConnGroupEntry *group, int *err_no)
{
    SFCMServerEntry *master;
    ConnectionInfo *conn;
    SFCMServerPtrArray *alives;

    master = (SFCMServerEntry *)FC_ATOMIC_GET(group->master);
    if (master != NULL) {
        if ((conn=make_connection(cm, master->addr_array,
                        err_no)) != NULL)
        {
            alives = (SFCMServerPtrArray *)FC_ATOMIC_GET(group->alives);
            set_connection_params(conn, master, alives);
            return conn;
        } else {
            alives = (SFCMServerPtrArray *)FC_ATOMIC_GET(group->alives);
            if (alives != NULL) {
                remove_from_alives(cm, group, alives, master);
            }
            __sync_bool_compare_and_swap(&group->master, master, NULL);
        }
    }

    *err_no = SF_RETRIABLE_ERROR_NO_SERVER;
    return NULL;
}

static inline ConnectionInfo *make_readable_connection(SFConnectionManager *cm,
        SFCMConnGroupEntry *group, SFCMServerPtrArray *alives,
        const int index, int *err_no)
{
    ConnectionInfo *conn;

    if ((conn=make_connection(cm, alives->servers[index]->
                    addr_array, err_no)) == NULL)
    {
        remove_from_alives(cm, group, alives, alives->servers[index]);
    } else {
        set_connection_params(conn, alives->servers[index], alives);
    }

    return conn;
}

static ConnectionInfo *get_master_connection(SFConnectionManager *cm,
        const int group_index, int *err_no)
{
    SFCMConnGroupEntry *group;
    ConnectionInfo *conn;
    SFNetRetryIntervalContext net_retry_ctx;
    int retry_count;

    group = cm->groups.entries + group_index;
    sf_init_net_retry_interval_context(&net_retry_ctx,
            &cm->common_cfg->net_retry_cfg.interval_mm,
            &cm->common_cfg->net_retry_cfg.connect);
    retry_count = 0;
    while (1) {
        if ((conn=make_master_connection(cm, group, err_no)) != NULL) {
            return conn;
        }

        /*
        logInfo("file: "__FILE__", line: %d, "
                "retry_count: %d, interval_ms: %d, data group id: %d, "
                "master: %p, alive count: %d, all count: %d", __LINE__,
                retry_count, net_retry_ctx.interval_ms, group->id,
                FC_ATOMIC_GET(group->master), ((SFCMServerPtrArray *)
                    FC_ATOMIC_GET(group->alives))->count, group->all.count);
         */

        *err_no = get_group_servers(cm, group);
        if (*err_no == 0) {
            *err_no = SF_RETRIABLE_ERROR_NO_SERVER;  //for try again
        }
        SF_NET_RETRY_CHECK_AND_SLEEP(net_retry_ctx,
                cm->common_cfg->net_retry_cfg.
                connect.times, ++retry_count, *err_no);
    }

    logError("file: "__FILE__", line: %d, "
            "get_master_connection fail, group id: %d, retry count: %d, "
            "errno: %d", __LINE__, group->id, retry_count, *err_no);
    return NULL;
}

static ConnectionInfo *get_readable_connection(SFConnectionManager *cm,
        const int group_index, int *err_no)
{
    SFCMConnGroupEntry *group;
    SFCMServerPtrArray *alives;
    ConnectionInfo *conn;
    SFNetRetryIntervalContext net_retry_ctx;
    uint32_t index;
    int retry_count;

    group = cm->groups.entries + group_index;
    if ((cm->common_cfg->read_rule == sf_data_read_rule_master_only) ||
            (group->all.count == 1))
    {
        return get_master_connection(cm, group_index, err_no);
    }

    sf_init_net_retry_interval_context(&net_retry_ctx,
            &cm->common_cfg->net_retry_cfg.interval_mm,
            &cm->common_cfg->net_retry_cfg.connect);
    retry_count = 0;
    while (1) {
        alives = (SFCMServerPtrArray *)FC_ATOMIC_GET(group->alives);
        if (alives->count > 0) {
            index = rand() % alives->count;
            if ((conn=make_readable_connection(cm, group, alives,
                            index, err_no)) != NULL)
            {
                return conn;
            }
        }

        if (cm->common_cfg->read_rule == sf_data_read_rule_slave_first) {
            if ((conn=make_master_connection(cm, group, err_no)) != NULL) {
                return conn;
            }
        }

        *err_no = get_group_servers(cm, group);
        if (*err_no == 0) {
            *err_no = SF_RETRIABLE_ERROR_NO_SERVER;  //for try again
        }
        SF_NET_RETRY_CHECK_AND_SLEEP(net_retry_ctx,
                cm->common_cfg->net_retry_cfg.
                connect.times, ++retry_count, *err_no);
    }

    logError("file: "__FILE__", line: %d, "
            "get_readable_connection fail, retry count: %d, errno: %d",
            __LINE__, retry_count, *err_no);
    return NULL;
}

static void release_connection(SFConnectionManager *cm,
        ConnectionInfo *conn)
{
    SFConnectionParameters *cparam;
    cparam = (SFConnectionParameters *)conn->args;
    if (cparam->cm.sentry != NULL) {
        cparam->cm.sentry = NULL;
        cparam->cm.old_alives = NULL;
    }

    conn_pool_close_connection_ex(&cm->cpool, conn, false);
}

static void close_connection(SFConnectionManager *cm, ConnectionInfo *conn)
{
    SFConnectionParameters *cparam;
    SFCMServerEntry *server;
    SFCMConnGroupEntry *group;

    cparam = (SFConnectionParameters *)conn->args;
    if (cparam->cm.sentry != NULL) {
        server = cparam->cm.sentry;
        group = cm->groups.entries + server->group_index;
        if (cparam->cm.old_alives != NULL) {
            remove_from_alives(cm, group, cparam->cm.old_alives, server);
            cparam->cm.old_alives = NULL;
        }
        __sync_bool_compare_and_swap(&group->master, server, NULL);
        cparam->cm.sentry = NULL;
    }

    conn_pool_close_connection_ex(&cm->cpool, conn, true);
}

static ConnectionInfo *get_leader_connection(SFConnectionManager *cm,
        FCServerInfo *server, int *err_no)
{
    ConnectionInfo *conn;
    SFClientServerEntry leader;
    SFNetRetryIntervalContext net_retry_ctx;
    int i;
    int connect_fails;

    sf_init_net_retry_interval_context(&net_retry_ctx,
            &cm->common_cfg->net_retry_cfg.interval_mm,
            &cm->common_cfg->net_retry_cfg.connect);
    i = connect_fails = 0;
    while (1) {
        do {
            if ((conn=get_server_connection(cm, server,
                            err_no)) == NULL)
            {
                connect_fails++;
                break;
            }

            if ((*err_no=sf_proto_get_leader(conn, cm->common_cfg->
                    network_timeout, &leader)) != 0)
            {
                close_connection(cm, conn);
                break;
            }

            if (FC_CONNECTION_SERVER_EQUAL1(*conn, leader.conn)) {
                return conn;
            }
            release_connection(cm, conn);
            if ((conn=get_spec_connection(cm, &leader.conn,
                            err_no)) == NULL)
            {
                break;
            }

            return conn;
        } while (0);

        if (connect_fails == 2) {
            break;
        }

        SF_NET_RETRY_CHECK_AND_SLEEP(net_retry_ctx,
                cm->common_cfg->net_retry_cfg.
                connect.times, ++i, *err_no);
    }

    logWarning("file: "__FILE__", line: %d, "
            "get_leader_connection fail, server id: %d, %s:%u, errno: %d",
            __LINE__, server->id, server->group_addrs[cm->server_group_index].
            address_array.addrs[0]->conn.ip_addr, server->group_addrs[cm->
            server_group_index].address_array.addrs[0]->conn.port, *err_no);
    return NULL;
}

const struct sf_connection_parameters *sf_cm_get_connection_params(
        SFConnectionManager *cm, ConnectionInfo *conn)
{
    return (SFConnectionParameters *)conn->args;
}

int sf_cm_validate_connection_callback(ConnectionInfo *conn, void *args)
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

static int init_group_array(SFConnectionManager *cm,
        SFCMConnGroupArray *garray, const int group_count)
{
    int bytes;

    bytes = sizeof(SFCMConnGroupEntry) * group_count;
    garray->entries = (SFCMConnGroupEntry *)fc_malloc(bytes);
    if (garray->entries == NULL) {
        return ENOMEM;
    }
    memset(garray->entries, 0, bytes);
    garray->count = group_count;
    return 0;
}

int sf_connection_manager_init_ex(SFConnectionManager *cm,
        const char *module_name, const SFClientCommonConfig *common_cfg,
        const int group_count, const int server_group_index,
        const int server_count, const int max_count_per_entry,
        const int max_idle_time, fc_connection_callback_func
        connect_done_callback, void *args, const bool bg_thread_enabled)
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
                    sf_cm_validate_connection_callback, cm,
                    sizeof(SFConnectionParameters))) != 0)
    {
        return result;
    }

    if ((result=init_group_array(cm, &cm->groups, group_count)) != 0) {
        return result;
    }

    if (bg_thread_enabled) {
        if ((result=common_blocked_queue_init(&cm->
                        alive_detect.queue)) != 0)
        {
            return result;
        }
    }

    cm->server_group_index = server_group_index;
    cm->module_name = module_name;
    cm->common_cfg = common_cfg;
    cm->alive_detect.bg_thread_enabled = bg_thread_enabled;
    cm->max_servers_per_group = 0;
    cm->extra = NULL;

    cm->ops.get_connection = get_connection;
    cm->ops.get_server_connection = get_server_connection;
    cm->ops.get_spec_connection = get_spec_connection;
    cm->ops.get_master_connection = get_master_connection;
    cm->ops.get_readable_connection = get_readable_connection;
    cm->ops.get_leader_connection = get_leader_connection;
    cm->ops.release_connection = release_connection;
    cm->ops.close_connection = close_connection;
    cm->ops.get_connection_params = sf_cm_get_connection_params;
    return 0;
}

int sf_connection_manager_add(SFConnectionManager *cm, const int group_id,
        FCServerInfo **servers, const int count)
{
    SFCMConnGroupEntry *group;
    FCServerInfo **server;
    FCServerInfo **end;
    SFCMServerEntry *entry;
    int group_index;

    if (group_id < 1) {
        logError("file: "__FILE__", line: %d, "
                "invalid group id: %d < 1",
                __LINE__, group_id);
        return EINVAL;
    }
    if (group_id > cm->groups.count) {
        logError("file: "__FILE__", line: %d, "
                "invalid group id: %d > group count: %d",
                __LINE__, group_id, cm->groups.count);
        return EINVAL;
    }

    group_index = group_id - 1;
    group = cm->groups.entries + group_index;
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
        entry->group_index = group_index;
        entry->addr_array = &(*server)->group_addrs[
            cm->server_group_index].address_array;
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
        push_to_detect_queue(cm, group, new_alives);
        fast_mblock_free_object(&cm->sptr_array_allocator, new_alives);
        return 0;
    }

    alive_array_cas(cm, group, old_alives, new_alives);
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

static void deal_nodes(SFConnectionManager *cm,
        struct common_blocked_node *node)
{
    SFCMConnGroupEntry *group;
    SFCMServerPtrArray *alives;

    do {
        group = (SFCMConnGroupEntry *)node->data;
        __sync_bool_compare_and_swap(&group->in_queue, 1, 0);
        alives = (SFCMServerPtrArray *)FC_ATOMIC_GET(group->alives);
        if (alives->count < group->all.count) {
            logDebug("file: "__FILE__", line: %d, "
                    "[%s] group_id: %d, alive server count: %d, "
                    "all server count: %d", __LINE__, cm->module_name,
                    group->id, alives->count, group->all.count);

            if (get_group_servers(cm, group) != 0) {
                push_to_detect_queue(cm, group, (SFCMServerPtrArray *)
                        FC_ATOMIC_GET(group->alives));
            }
        }

        node = node->next;
    } while (node != NULL);
}

static void *connection_manager_thread_func(void *arg)
{
    SFConnectionManager *cm;
    struct common_blocked_node *head;

#ifdef OS_LINUX
    prctl(PR_SET_NAME, "cm-alive-detect");
#endif

    cm = (SFConnectionManager *)arg;
    logDebug("file: "__FILE__", line: %d, "
            "[%s] connection manager thread start",
            __LINE__, cm->module_name);

    while (1) {
        sleep(1);
        if ((head=common_blocked_queue_pop_all_nodes(&cm->
                        alive_detect.queue)) == NULL)
        {
            continue;
        }

        deal_nodes(cm, head);
        common_blocked_queue_free_all_nodes(&cm->alive_detect.queue, head);
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

int sf_connection_manager_prepare(SFConnectionManager *cm)
{
    int result;
    int element_size;
    SFCMConnGroupEntry *group;
    SFCMConnGroupEntry *end;
    SFCMServerPtrArray *sptr_array;

    element_size = sizeof(SFCMServerPtrArray) +
        sizeof(SFCMServerEntry *) * cm->max_servers_per_group;
    if ((result=fast_mblock_init_ex1(&cm->sptr_array_allocator,
                    "server-ptr-array", element_size, 4 * 1024, 0,
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

    return 0;
}

int sf_connection_manager_start(SFConnectionManager *cm)
{
    pthread_t tid;

    if (cm->alive_detect.bg_thread_enabled) {
        return fc_create_thread(&tid, connection_manager_thread_func,
                cm, SF_G_THREAD_STACK_SIZE);
    } else {
        return 0;
    }
}
