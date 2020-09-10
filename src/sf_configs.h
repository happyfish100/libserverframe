//sf_global.h

#ifndef _SF_GLOBAL_H
#define _SF_GLOBAL_H

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

#ifdef __cplusplus
extern "C" {
#endif

int sf_load_net_retry_config(SFNetRetryConfig *net_retry_cfg,
        IniFullContext *ini_ctx);

void sf_net_retry_config_to_string(SFNetRetryConfig *net_retry_cfg,
        char *output, const int size);

#ifdef __cplusplus
}
#endif

#endif

