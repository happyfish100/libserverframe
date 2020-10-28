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

#include "fastcommon/logger.h"
#include "fastcommon/sched_thread.h"

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

#define sf_parse_daemon_mode_and_action(argc, argv, daemon_mode, action) \
    sf_parse_daemon_mode_and_action_ex(argc, argv, daemon_mode, action, "start")

#ifdef __cplusplus
extern "C" {
#endif

int64_t getticks() ;

void log_plus(const int priority, const char* file, int line, const char* fmt, ...);

int sf_printbuffer(char* buffer,int32_t len);

void sf_usage(const char *program);

void sf_parse_daemon_mode_and_action_ex(int argc, char *argv[],
        bool *daemon_mode, char **action, const char *default_action);

int sf_logger_init(LogContext *pContext, const char *filename_prefix);

ScheduleEntry *sf_logger_set_schedule_entry(struct log_context *pContext,
        ScheduleEntry *pScheduleEntry);

const char *sf_strerror(const int errnum);

#ifdef __cplusplus
}
#endif

#endif
