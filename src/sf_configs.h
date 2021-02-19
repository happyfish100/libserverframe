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

void sf_load_read_rule_config_ex(SFDataReadRule *rule,
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

#define sf_load_read_rule_config(rule, ini_ctx) \
    sf_load_read_rule_config_ex(rule, ini_ctx, sf_data_read_rule_master_only)

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

