//sf_configs.h

#ifndef _SF_CONFIGS_H
#define _SF_CONFIGS_H

#include "fastcommon/common_define.h"
#include "fastcommon/ini_file_reader.h"
#include "sf_define.h"
#include "sf_types.h"

typedef enum sf_net_retry_interval_mode {
    sf_net_retry_interval_mode_fixed,
    sf_net_retry_interval_mode_multiple
} SFNetRetryIntervalMode;

typedef struct sf_net_retry_interval_mode_max_pair {
    SFNetRetryIntervalMode mode;
    int max_interval_ms;
} SFNetRetryIntervalModeMaxPair;

typedef struct sf_net_retry_times_interval_pair {
    int times;
    int interval_ms;
} SFNetRetryTimesIntervalPair;

typedef struct sf_net_retry_config {
    SFNetRetryIntervalModeMaxPair interval_mm;
    SFNetRetryTimesIntervalPair connect;
    SFNetRetryTimesIntervalPair network;
} SFNetRetryConfig;

typedef struct sf_net_retry_interval_context {
    SFNetRetryIntervalModeMaxPair *mm;
    SFNetRetryTimesIntervalPair *ti;
    int interval_ms;
} SFNetRetryIntervalContext;

typedef enum sf_data_read_rule {
    sf_data_read_rule_any_available,
    sf_data_read_rule_slave_first,
    sf_data_read_rule_master_only,
} SFDataReadRule;

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
        SFNetRetryIntervalContext *ctx, SFNetRetryIntervalModeMaxPair *mm,
        SFNetRetryTimesIntervalPair *ti)
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

void sf_load_read_rule_config(SFDataReadRule *rule, IniFullContext *ini_ctx);

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

