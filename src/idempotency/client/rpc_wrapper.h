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


#ifndef _IDEMPOTENCY_RPC_WRAPPER_H
#define _IDEMPOTENCY_RPC_WRAPPER_H

#include "../../sf_configs.h"

#define SF_CLIENT_IDEMPOTENCY_UPDATE_WRAPPER(client_ctx, conn_manager, \
        GET_MASTER_CONNECTION, get_conn_arg1, update_callback, ...) \
    ConnectionInfo *conn;  \
    IdempotencyClientChannel *old_channel;  \
    int result;  \
    int conn_result;  \
    int i;       \
    bool idempotency_enabled;  \
    uint64_t req_id;  \
    SFNetRetryIntervalContext net_retry_ctx;  \
    \
    if ((conn=GET_MASTER_CONNECTION(conn_manager, \
                    get_conn_arg1, &result)) == NULL) \
    { \
        return SF_UNIX_ERRNO(result, EIO); \
    } \
    connection_params = (conn_manager)->ops. \
            get_connection_params(conn_manager, conn); \
    idempotency_enabled = client_ctx->idempotency_enabled && \
            connection_params != NULL;  \
    \
    sf_init_net_retry_interval_context(&net_retry_ctx, \
            &client_ctx->common_cfg.net_retry_cfg.interval_mm,    \
            &client_ctx->common_cfg.net_retry_cfg.network);       \
    \
    while (1) {  \
        if (idempotency_enabled) {   \
            req_id = idempotency_client_channel_next_seq_id(  \
                    connection_params->channel); \
        } else {  \
            req_id = 0;  \
        }  \
    \
        old_channel = connection_params != NULL ? \
             connection_params->channel : NULL;   \
        i = 0; \
        while (1) { \
            if (idempotency_enabled) {  \
                result = idempotency_client_channel_check_wait(  \
                        connection_params->channel);  \
            } else {  \
                result = 0;  \
            }  \
    \
            if (result == 0) {  \
                if ((result=update_callback(client_ctx,  \
                                conn, req_id, ##__VA_ARGS__)) == 0) \
                {  \
                    break;  \
                }  \
            }  \
    \
            conn_result = result;  \
            if (result == SF_RETRIABLE_ERROR_CHANNEL_INVALID && \
                    idempotency_enabled)  \
            {  \
                if (idempotency_client_channel_check_wait(    \
                            connection_params->channel) == 0) \
                { \
                    if ((conn_result=sf_proto_rebind_idempotency_channel( \
                                conn, connection_params->channel->id, \
                                connection_params->channel->key,      \
                                client_ctx->common_cfg.network_timeout)) == 0)   \
                    { \
                        continue; \
                    } \
                } \
            }  \
    \
            SF_NET_RETRY_CHECK_AND_SLEEP(net_retry_ctx, client_ctx-> \
                    common_cfg.net_retry_cfg.network.times, ++i, result); \
    /* \
            logInfo("file: "__FILE__", line: %d, func: %s, "  \
                    "net retry result: %d, retry count: %d",  \
                    __LINE__, __FUNCTION__, result, i);       \
    */ \
            SF_CLIENT_RELEASE_CONNECTION(conn_manager, conn, conn_result); \
            if ((conn=GET_MASTER_CONNECTION(conn_manager,  \
                            get_conn_arg1, &result)) == NULL)  \
            {  \
                return SF_UNIX_ERRNO(result, EIO);  \
            }  \
    \
            connection_params = (conn_manager)->ops. \
                get_connection_params(conn_manager, conn);  \
            if (connection_params != NULL && connection_params->channel != \
                    old_channel) \
            {  \
                break; \
            }  \
        }  \
    \
        if (connection_params != NULL && connection_params->channel !=  \
                old_channel)   \
        { /* master changed */ \
            continue; \
        } \
    \
        if (idempotency_enabled && !SF_IS_SERVER_RETRIABLE_ERROR(result)) { \
            idempotency_client_channel_push( \
                    connection_params->channel, req_id); \
        } \
        break; \
    } \
    \
    SF_CLIENT_RELEASE_CONNECTION(conn_manager, conn, result); \
    return SF_UNIX_ERRNO(result, EIO)


#define SF_CLIENT_IDEMPOTENCY_QUERY_WRAPPER(client_ctx, conn_manager, \
        GET_READABLE_CONNECTION, get_conn_arg1, query_callback, ...) \
    ConnectionInfo *conn;  \
    int result;  \
    int i;       \
    SFNetRetryIntervalContext net_retry_ctx;  \
    \
    if ((conn=GET_READABLE_CONNECTION(conn_manager, \
                    get_conn_arg1, &result)) == NULL) \
    { \
        return SF_UNIX_ERRNO(result, EIO); \
    } \
    \
    sf_init_net_retry_interval_context(&net_retry_ctx, \
            &client_ctx->common_cfg.net_retry_cfg.interval_mm,    \
            &client_ctx->common_cfg.net_retry_cfg.network);       \
    i = 0; \
    while (1) { \
        if ((result=query_callback(client_ctx,  \
                        conn, ##__VA_ARGS__)) == 0) \
        {  \
            break;  \
        }  \
        SF_NET_RETRY_CHECK_AND_SLEEP(net_retry_ctx, client_ctx-> \
                common_cfg.net_retry_cfg.network.times, ++i, result); \
    /* \
        logInfo("file: "__FILE__", line: %d, func: %s, "  \
                "net retry result: %d, retry count: %d",  \
                __LINE__, __FUNCTION__, result, i);       \
    */ \
        SF_CLIENT_RELEASE_CONNECTION(conn_manager, conn, result); \
        if ((conn=GET_READABLE_CONNECTION(conn_manager,  \
                        get_conn_arg1, &result)) == NULL)  \
        {  \
            return SF_UNIX_ERRNO(result, EIO);  \
        }  \
    } \
    \
    SF_CLIENT_RELEASE_CONNECTION(conn_manager, conn, result); \
    return SF_UNIX_ERRNO(result, EIO)


#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif
