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

#include <limits.h>
#include "fastcommon/fast_buffer.h"
#include "fastcommon/md5.h"
#include "sf_cluster_cfg.h"

static int calc_cluster_config_sign(SFClusterConfig *cluster)
{
    FastBuffer buffer;
    int result;

    if ((result=fast_buffer_init_ex(&buffer, 1024)) != 0) {
        return result;
    }
    fc_server_to_config_string(&cluster->server_cfg, &buffer);
    my_md5_buffer(buffer.data, buffer.length, cluster->md5_digest);

    /*
    {
    char hex_buff[2 * sizeof(cluster->md5_digest) + 1];
    logInfo("cluster config length: %d, sign: %s", buffer.length,
            bin2hex((const char *)cluster->md5_digest,
                sizeof(cluster->md5_digest), hex_buff));
    }
    */

    fast_buffer_destroy(&buffer);
    return 0;
}

static int find_group_indexes_in_cluster_config(SFClusterConfig *cluster,
        const char *filename)
{
    cluster->cluster_group_index = fc_server_get_group_index(
            &cluster->server_cfg, "cluster");
    if (cluster->cluster_group_index < 0) {
        logError("file: "__FILE__", line: %d, "
                "cluster config file: %s, cluster group "
                "not configurated", __LINE__, filename);
        return ENOENT;
    }

    cluster->service_group_index = fc_server_get_group_index(
            &cluster->server_cfg, "service");
    if (cluster->service_group_index < 0) {
        logError("file: "__FILE__", line: %d, "
                "cluster config file: %s, service group "
                "not configurated", __LINE__, filename);
        return ENOENT;
    }

    return 0;
}

static int load_server_cfg(SFClusterConfig *cluster,
        const char *cluster_filename, const int default_port,
        const bool share_between_groups)
{
    IniContext ini_context;
    const int min_hosts_each_group = 1;
    int result;

    if ((result=iniLoadFromFile(cluster_filename, &ini_context)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "load conf file \"%s\" fail, ret code: %d",
                __LINE__, cluster_filename, result);
        return result;
    }

    result = fc_server_load_from_ini_context_ex(&cluster->server_cfg,
            &ini_context, cluster_filename, default_port,
            min_hosts_each_group, share_between_groups);

    iniFreeContext(&ini_context);
    return result;
}

int sf_load_cluster_config_by_file(SFClusterConfig *cluster,
        const char *full_cluster_filename, const int default_port,
        const bool share_between_groups, const bool calc_sign)
{
    int result;

    if ((result=load_server_cfg(cluster, full_cluster_filename,
                    default_port, share_between_groups)) != 0)
    {
        return result;
    }

    if ((result=find_group_indexes_in_cluster_config(cluster,
                    full_cluster_filename)) != 0)
    {
        return result;
    }

    if (calc_sign) {
        if ((result=calc_cluster_config_sign(cluster)) != 0) {
            return result;
        }
    }

    return 0;
}

int sf_load_cluster_config_ex(SFClusterConfig *cluster, IniFullContext
        *ini_ctx, const int default_port, char *full_cluster_filename,
        const int size)
{
    const bool share_between_groups = true;
    char *cluster_config_filename;
    
    cluster_config_filename = iniGetStrValue(ini_ctx->section_name,
            "cluster_config_filename", ini_ctx->context);
    if (cluster_config_filename == NULL || *cluster_config_filename == '\0') {
        logError("file: "__FILE__", line: %d, "
                "config file: %s, item \"cluster_config_filename\" "
                "not exist or empty", __LINE__, ini_ctx->filename);
        return ENOENT;
    }
    
    resolve_path(ini_ctx->filename, cluster_config_filename,
            full_cluster_filename, size);
    return sf_load_cluster_config_by_file(cluster, full_cluster_filename,
            default_port, share_between_groups, true);
}
