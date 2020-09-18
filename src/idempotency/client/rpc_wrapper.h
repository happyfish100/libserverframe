
#ifndef _IDEMPOTENCY_RPC_WRAPPER_H
#define _IDEMPOTENCY_RPC_WRAPPER_H

#include "../../sf_configs.h"

#define SF_CLIENT_IDEMPOTENCY_UPDATE_WARPER(client_ctx, \
        GET_MASTER_CONNECTION, get_conn_arg1, update_callback, ...) \
    ConnectionInfo *conn;  \
    IdempotencyClientChannel *old_channel;  \
    int result;  \
    int i;       \
    uint64_t req_id;  \
    SFNetRetryIntervalContext net_retry_ctx;  \
    \
    if ((conn=GET_MASTER_CONNECTION(client_ctx, \
                    get_conn_arg1, &result)) == NULL) \
    { \
        return SF_UNIX_ERRNO(result, EIO); \
    } \
    connection_params = client_ctx->conn_manager. \
            get_connection_params(client_ctx, conn); \
    \
    sf_init_net_retry_interval_context(&net_retry_ctx, \
            &client_ctx->net_retry_cfg.interval_mm,    \
            &client_ctx->net_retry_cfg.network);       \
    \
    while (1) {  \
        if (client_ctx->idempotency_enabled) {   \
            req_id = idempotency_client_channel_next_seq_id(  \
                    connection_params->channel); \
        } else {  \
            req_id = 0;  \
        }  \
    \
        old_channel = connection_params->channel; \
        i = 0; \
        while (1) { \
            if (client_ctx->idempotency_enabled) {  \
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
            if (result == SF_RETRIABLE_ERROR_CHANNEL_INVALID && \
                    client_ctx->idempotency_enabled)  \
            {  \
                idempotency_client_channel_check_reconnect( \
                        connection_params->channel);  \
            }  \
    \
            SF_NET_RETRY_CHECK_AND_SLEEP(net_retry_ctx, client_ctx-> \
                    net_retry_cfg.network.times, ++i, result); \
    \
            logInfo("file: "__FILE__", line: %d, func: %s, "  \
                    "net retry result: %d, retry count: %d",  \
                    __LINE__, __FUNCTION__, result, i);       \
    \
            SF_CLIENT_RELEASE_CONNECTION(client_ctx, conn, result); \
            if ((conn=GET_MASTER_CONNECTION(client_ctx,  \
                            get_conn_arg1, &result)) == NULL)  \
            {  \
                return SF_UNIX_ERRNO(result, EIO);  \
            }  \
    \
            connection_params = client_ctx->conn_manager. \
                get_connection_params(client_ctx, conn);  \
            if (connection_params->channel != old_channel) { \
                break; \
            }  \
        }  \
    \
        if (connection_params->channel != old_channel) { /* master changed */ \
            sf_reset_net_retry_interval(&net_retry_ctx); \
            continue; \
        } \
    \
        if (client_ctx->idempotency_enabled) { \
            idempotency_client_channel_push( \
                    connection_params->channel, req_id); \
        } \
        break; \
    } \
    \
    SF_CLIENT_RELEASE_CONNECTION(client_ctx, conn, result); \
    return SF_UNIX_ERRNO(result, EIO)


#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif
