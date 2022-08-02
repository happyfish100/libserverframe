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

//sf_configs.h

#ifndef _SF_CONFIGS_H
#define _SF_CONFIGS_H

#include "fastcommon/common_define.h"
#include "fastcommon/ini_file_reader.h"
#include "sf_define.h"
#include "sf_types.h"

typedef struct sf_net_retry_interval_context {
    const SFNetRetryIntervalModeMaxPair *mm;
    const SFNetRetryTimesIntervalPair *ti;
    int interval_ms;
} SFNetRetryIntervalContext;

#ifdef __cplusplus
extern "C" {
#endif

int sf_load_net_retry_config(SFNetRetryConfig *net_retry_cfg,
        IniFullContext *ini_ctx);

void sf_net_retry_config_to_string(SFNetRetryConfig *net_retry_cfg,
        char *output, const int size);

static inline void sf_reset_net_retry_interval(SFNetRetryIntervalContext *ctx)
{
    ctx->interval_ms = FC_MIN(ctx->ti->interval_ms, ctx->mm->max_interval_ms);
}

static inline void sf_init_net_retry_interval_context(
        SFNetRetryIntervalContext *ctx, const SFNetRetryIntervalModeMaxPair *mm,
        const SFNetRetryTimesIntervalPair *ti)
{
    ctx->mm = mm;
    ctx->ti = ti;
    sf_reset_net_retry_interval(ctx);
}

static inline int sf_calc_next_retry_interval(SFNetRetryIntervalContext *ctx)
{
    if (ctx->mm->mode == sf_net_retry_interval_mode_multiple) {
        if (ctx->interval_ms < ctx->mm->max_interval_ms) {
            ctx->interval_ms *= 2;
            if (ctx->interval_ms > ctx->mm->max_interval_ms) {
                ctx->interval_ms = ctx->mm->max_interval_ms;
            }
        }
    }

    return ctx->interval_ms;
}

int sf_load_read_rule_config_ex(SFDataReadRule *rule,
        IniFullContext *ini_ctx, const SFDataReadRule def_rule);

static inline const char *sf_get_read_rule_caption(
        const SFDataReadRule read_rule)
{
    switch (read_rule) {
        case sf_data_read_rule_any_available:
            return "any available";
        case sf_data_read_rule_slave_first:
            return "slave first";
        case sf_data_read_rule_master_only:
            return "master only";
        default:
            return "unknown";
    }
}

int sf_load_election_quorum_config_ex(SFElectionQuorum *quorum,
        IniFullContext *ini_ctx, const SFElectionQuorum def_quorum);

static inline const char *sf_get_election_quorum_caption(
        const SFElectionQuorum quorum)
{
    switch (quorum) {
        case sf_election_quorum_auto:
            return "auto";
        case sf_election_quorum_any:
            return "any";
        case sf_election_quorum_majority:
            return "majority";
        default:
            return "unknown";
    }
}

static inline bool sf_election_quorum_check(const SFElectionQuorum quorum,
        const bool vote_node_enabled, const int total_count,
        const int active_count)
{
    switch (quorum) {
        case sf_election_quorum_any:
            return active_count > 0;
        case sf_election_quorum_auto:
            if (total_count % 2 == 0 && !vote_node_enabled) {
                return active_count > 0;  //same as sf_election_quorum_any
            }
            //continue
        case sf_election_quorum_majority:
            if (active_count == total_count) {
                return true;
            } else {
                return active_count > total_count / 2;
            }
    }
}

int sf_load_replication_quorum_config_ex(SFReplicationQuorum *quorum,
        IniFullContext *ini_ctx, const SFReplicationQuorum def_quorum);

static inline const char *sf_get_replication_quorum_caption(
        const SFReplicationQuorum quorum)
{
    switch (quorum) {
        case sf_replication_quorum_auto:
            return "auto";
        case sf_replication_quorum_any:
            return "any";
        case sf_replication_quorum_majority:
            return "majority";
        case sf_replication_quorum_smart:
            return "smart";
        default:
            return "unknown";
    }
}

#define SF_REPLICATION_QUORUM_MAJORITY(server_count, success_count) \
    ((success_count == server_count) || (success_count > server_count / 2))

static inline bool sf_replication_quorum_check(const SFReplicationQuorum
        quorum, const int server_count, const int success_count)
{
    switch (quorum) {
        case sf_replication_quorum_any:
            return true;
        case sf_replication_quorum_auto:
            if (server_count % 2 == 0) {
                return true;  //same as sf_replication_quorum_any
            }
            //continue
        case sf_replication_quorum_smart:
        case sf_replication_quorum_majority:
            return SF_REPLICATION_QUORUM_MAJORITY(
                    server_count, success_count);
    }
}

#define sf_load_read_rule_config(rule, ini_ctx) \
    sf_load_read_rule_config_ex(rule, ini_ctx, sf_data_read_rule_master_only)

#define sf_load_election_quorum_config(quorum, ini_ctx) \
    sf_load_election_quorum_config_ex(quorum, ini_ctx, sf_election_quorum_auto)

#define sf_load_replication_quorum_config(quorum, ini_ctx) \
    sf_load_replication_quorum_config_ex(quorum, ini_ctx,  \
            sf_replication_quorum_auto)

#define SF_ELECTION_QUORUM_NEED_REQUEST_VOTE_NODE(quorum, \
        vote_node_enabled, server_count, active_count) \
    (active_count < server_count && vote_node_enabled && \
     quorum != sf_election_quorum_any && server_count % 2 == 0)

#define SF_ELECTION_QUORUM_NEED_CHECK_VOTE_NODE(quorum, \
        vote_node_enabled, server_count) \
    (vote_node_enabled && quorum != sf_election_quorum_any \
     && server_count % 2 == 0)

#define SF_REPLICATION_QUORUM_NEED_MAJORITY(quorum, server_count) \
    (server_count > 1 && (quorum != sf_replication_quorum_any))

#define SF_REPLICATION_QUORUM_NEED_DETECT(quorum, server_count)  \
    (server_count % 2 == 0 && (quorum == sf_replication_quorum_smart || \
                               quorum == sf_replication_quorum_auto))

#define SF_NET_RETRY_FINISHED(retry_times, counter, result)  \
        !((SF_IS_RETRIABLE_ERROR(result) && ((retry_times > 0 &&  \
                    counter <= retry_times) || (retry_times < 0))))

#define SF_NET_RETRY_CHECK_AND_SLEEP(net_retry_ctx, \
        retry_times, counter, result) \
    if (SF_NET_RETRY_FINISHED(retry_times, counter, result)) { \
        break;  \
    }  \
    do {  \
        sf_calc_next_retry_interval(&net_retry_ctx); \
        if (net_retry_ctx.interval_ms > 0) {         \
            fc_sleep_ms(net_retry_ctx.interval_ms);  \
        } \
    } while (0)


#ifdef __cplusplus
}
#endif

#endif

