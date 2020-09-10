#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "sf_configs.h"

#define DEFAULT_RETRY_MAX_INTERVAL_MS      5000
#define DEFAULT_CONNECT_RETRY_TIMES          10
#define DEFAULT_CONNECT_RETRY_INTERVAL_MS   100
#define DEFAULT_NETWORK_RETRY_TIMES          10
#define DEFAULT_NETWORK_RETRY_INTERVAL_MS   100

int sf_load_net_retry_config(SFNetRetryConfig *net_retry_cfg,
        IniFullContext *ini_ctx)
{
    char *retry_interval_mode;
    retry_interval_mode = iniGetStrValue(ini_ctx->section_name,
            "retry_interval_mode", ini_ctx->context);
    if (retry_interval_mode == NULL || *retry_interval_mode == '\0') {
        net_retry_cfg->retry_interval_mode =
            sf_net_retry_interval_mode_multiple;
    } else if (strncasecmp(retry_interval_mode, "fixed", 5) == 0) {
        net_retry_cfg->retry_interval_mode =
            sf_net_retry_interval_mode_fixed;
    } else if (strncasecmp(retry_interval_mode, "multi", 5) == 0) {
        net_retry_cfg->retry_interval_mode =
            sf_net_retry_interval_mode_multiple;
    } else {
        logWarning("file: "__FILE__", line: %d, "
                "config file: %s, unkown retry_interval_mode: %s, "
                "set to multiple", __LINE__, ini_ctx->filename,
                retry_interval_mode);
        net_retry_cfg->retry_interval_mode =
            sf_net_retry_interval_mode_multiple;
    }

    net_retry_cfg->retry_max_interval_ms = iniGetIntValue(
            ini_ctx->section_name, "retry_max_interval_ms",
            ini_ctx->context, DEFAULT_RETRY_MAX_INTERVAL_MS);

    net_retry_cfg->connect_retry_times = iniGetIntValue(
            ini_ctx->section_name, "connect_retry_times",
            ini_ctx->context, DEFAULT_CONNECT_RETRY_TIMES);

    net_retry_cfg->connect_retry_interval_ms = iniGetIntValue(
            ini_ctx->section_name, "connect_retry_interval_ms",
            ini_ctx->context, DEFAULT_CONNECT_RETRY_INTERVAL_MS);

    net_retry_cfg->network_retry_times = iniGetIntValue(
            ini_ctx->section_name, "network_retry_times",
            ini_ctx->context, DEFAULT_NETWORK_RETRY_TIMES);

    net_retry_cfg->network_retry_interval_ms = iniGetIntValue(
            ini_ctx->section_name, "network_retry_interval_ms",
            ini_ctx->context, DEFAULT_NETWORK_RETRY_INTERVAL_MS);

    return 0;
}

void sf_net_retry_config_to_string(SFNetRetryConfig *net_retry_cfg,
        char *output, const int size)
{
    snprintf(output, size, "retry_interval_mode=%s, "
            "retry_max_interval_ms=%d ms, connect_retry_times=%d, "
            "connect_retry_interval_ms=%d ms, network_retry_times=%d, "
            "network_retry_interval_ms=%d ms",
            (net_retry_cfg->retry_interval_mode ==
             sf_net_retry_interval_mode_fixed ? "fixed" : "multipl"),
            net_retry_cfg->retry_max_interval_ms,
            net_retry_cfg->connect_retry_times,
            net_retry_cfg->connect_retry_interval_ms,
            net_retry_cfg->network_retry_times,
            net_retry_cfg->network_retry_interval_ms);
}
