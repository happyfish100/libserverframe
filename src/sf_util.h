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

//sf_util.h

#ifndef _SF_UTIL_H_
#define _SF_UTIL_H_

#include <getopt.h>
#include "fastcommon/logger.h"
#include "fastcommon/sched_thread.h"
#include "sf_define.h"
#include "sf_types.h"
#include "sf_global.h"

#ifdef DEBUG_FLAG  /*only for format check*/

#define lemerg(...) snprintf(0,0,__VA_ARGS__), log_plus(LOG_EMERG, __FILE__, __LINE__, __VA_ARGS__)
#define lcrit(...) snprintf(0,0,__VA_ARGS__), log_plus(LOG_CRIT, __FILE__, __LINE__, __VA_ARGS__)
#define lalert(...) snprintf(0,0,__VA_ARGS__), log_plus(LOG_ALERT, __FILE__, __LINE__, __VA_ARGS__)
#define lerr(...) snprintf(0,0,__VA_ARGS__), log_plus(LOG_ERR, __FILE__, __LINE__, __VA_ARGS__)
#define lwarning(...) snprintf(0,0,__VA_ARGS__), log_plus(LOG_WARNING, __FILE__, __LINE__, __VA_ARGS__)
#define lnotice(...) snprintf(0,0,__VA_ARGS__), log_plus(LOG_NOTICE, __FILE__, __LINE__, __VA_ARGS__)
#define linfo(...) snprintf(0,0,__VA_ARGS__), log_plus(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define ldebug(...) snprintf(0,0,__VA_ARGS__), log_plus(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)

#else
#define lemerg(...) log_plus(LOG_EMERG, __FILE__, __LINE__, __VA_ARGS__)
#define lcrit(...) log_plus(LOG_CRIT, __FILE__, __LINE__, __VA_ARGS__)
#define lalert(...) log_plus(LOG_ALERT, __FILE__, __LINE__, __VA_ARGS__)
#define lerr(...) log_plus(LOG_ERR, __FILE__, __LINE__, __VA_ARGS__)
#define lwarning(...) log_plus(LOG_WARNING, __FILE__, __LINE__, __VA_ARGS__)
#define lnotice(...) log_plus(LOG_NOTICE, __FILE__, __LINE__, __VA_ARGS__)
#define linfo(...) log_plus(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define ldebug(...) log_plus(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)

#endif

#define returnif(b) if(b){ return b; }
#define breakif(b) if(b){ break; }

#define failvars int eln, eres; const char* emsg

#define gofailif(b, msg) if(b) { eln=__LINE__; emsg=msg; eres=(b); goto FAIL_; }

#define logfail() lerr("error at %s:%d errno: %d msg: %s errmsg: %s", \
__FILE__, eln, eres, emsg, strerror(eres))

#define dszoffset(cls, mem) ((char*)&((cls*)0)->mem -  ((char*)0))

#define sf_usage(program) sf_usage_ex(program, NULL)

#define sf_parse_daemon_mode_and_action(argc, argv, \
        version, daemon_mode, action) \
    sf_parse_daemon_mode_and_action_ex(argc, argv, \
            version, daemon_mode, action, "start", NULL)

#define SF_COMMON_OPT_STRING  "NVh"
#define SF_COMMON_LONG_OPTIONS  \
    {"no-daemon", no_argument, NULL, 'N'}, \
    {"version",   no_argument, NULL, 'V'},   \
    {"help",      no_argument, NULL, 'h'}

#ifdef __cplusplus
extern "C" {
#endif

int64_t getticks();

void log_plus(const int priority, const char *file,
        int line, const char *fmt, ...);

int sf_printbuffer(char *buffer,int32_t len);

void sf_usage_ex(const char *program, const SFCMDOption *other_options);

const char *sf_parse_daemon_mode_and_action_ex(int argc, char *argv[],
        const Version *version, bool *daemon_mode, char **action,
        const char *default_action, const SFCMDOption *other_options);

void sf_parse_cmd_option_bool(int argc, char *argv[],
        const string_t *short_option, const string_t *long_option,
        bool *value);

int sf_logger_init(LogContext *pContext, const char *filename_prefix);

ScheduleEntry *sf_logger_set_schedule_entry(struct log_context *pContext,
        SFLogConfig *log_cfg, ScheduleEntry *pScheduleEntry);

static inline void sf_setup_schedule(struct log_context *pContext,
        SFLogConfig *log_cfg, ScheduleArray *scheduleArray)
{
    ScheduleEntry *scheduleEntry;
    scheduleEntry = sf_logger_set_schedule_entry(pContext,
            log_cfg, scheduleArray->entries);
    scheduleArray->count = scheduleEntry - scheduleArray->entries;
}

static inline int sf_unify_errno(const int errnum)
{
    switch (errnum) {
        case EBUSY:
            return SF_ERROR_EBUSY;
        case EINVAL:
            return SF_ERROR_EINVAL;
        case EAGAIN:
            return SF_ERROR_EAGAIN;
        case EOVERFLOW:
            return SF_ERROR_EOVERFLOW;
        case EOPNOTSUPP:
            return SF_ERROR_EOPNOTSUPP;
        case ENODATA:
            return SF_ERROR_ENODATA;
        default:
            return errnum;
    }
}

static inline int sf_localize_errno(int errnum)
{
    if (SF_G_ERROR_HANDLER != NULL) {
        errnum = SF_G_ERROR_HANDLER(errnum);
    }

    switch (errnum) {
        case SF_ERROR_EBUSY:
            return EBUSY;
        case SF_ERROR_EINVAL:
            return EINVAL;
        case SF_ERROR_EAGAIN:
            return EAGAIN;
        case SF_ERROR_EOVERFLOW:
            return EOVERFLOW;
        case SF_ERROR_EOPNOTSUPP:
            return EOPNOTSUPP;
        case SF_ERROR_ENODATA:
            return ENODATA;
        case SF_SESSION_ERROR_NOT_EXIST:
            return EPERM;
        default:
            return errnum;
    }
}

const char *sf_strerror(const int errnum);

#ifdef __cplusplus
}
#endif

#endif
