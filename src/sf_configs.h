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

typedef struct sf_net_retry_config {
    SFNetRetryIntervalMode retry_interval_mode;
    int retry_max_interval_ms;
    int connect_retry_times;
    int connect_retry_interval_ms;
    int network_retry_times;
    int network_retry_interval_ms;
} SFNetRetryConfig;

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

#ifdef __cplusplus
}
#endif

#endif

