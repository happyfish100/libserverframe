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
#include "sf/sf_global.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "sf_connection_manager.h"

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

int sf_connection_manager_init(SFConnectionManager *cm, const int group_count,
        const int min_group_id, const int server_group_index,
        const SFDataReadRule read_rule)
{
    int result;

    if ((result=init_group_array(&cm->groups, group_count,
                    min_group_id)) != 0)
    {
        return result;
    }

    cm->server_group_index = server_group_index;
    cm->read_rule = read_rule;
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
        entry->server_id = (*server)->id;
        entry->addr_array = &(*server)->group_addrs[
            cm->server_group_index].address_array;
        entry->conn = NULL;
    }

    group->alives.servers = (SFCMServerEntry **)fc_malloc(
            sizeof(SFCMServerEntry *) * count);
    if (group->alives.servers == NULL) {
        return ENOMEM;
    }

    return 0;
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

int sf_connection_manager_start(SFConnectionManager *cm)
{
    pthread_t tid;
    return fc_create_thread(&tid, connection_manager_thread_func,
            cm, SF_G_THREAD_STACK_SIZE);
}
