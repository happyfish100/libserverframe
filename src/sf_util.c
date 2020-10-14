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


#ifdef OS_LINUX
#include <sys/syscall.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "sf_global.h"
#include "sf_util.h"

int64_t getticks() 
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

void log_plus(const int priority, const char* file,
              int line, const char* fmt, ...) 
{
    char buf[2048];
    int hlen;
    va_list ap;
#ifdef DEBUG_FLAG
    long tid;
#endif

    if (g_log_context.log_level < priority) {
        return;
    }

#ifdef DEBUG_FLAG

#ifdef OS_LINUX

#ifdef SYS_gettid
    tid = (long)syscall(SYS_gettid);
#else
    tid = (long)pthread_self();
#endif

#else
    tid = (long)pthread_self();
#endif

    hlen = snprintf(buf, sizeof(buf), "%s:%d %ld ", file, line, tid);

#else
    hlen = snprintf(buf, sizeof(buf), "%s:%d ", file, line);
#endif
    va_start(ap, fmt);
    hlen += vsnprintf(buf+hlen, sizeof(buf)-hlen, fmt, ap);
    va_end(ap);
    if (hlen >= sizeof(buf)) {
        hlen = sizeof(buf) - 1;
    }
    log_it_ex1(&g_log_context, priority, buf, hlen);
}

int sf_printbuffer(char* buffer,int32_t len)
{
    int i;
    if(buffer == NULL) {
        fprintf(stderr, "common-utils parameter is fail");
        return(-1);
    }

    for(i=0; i<len; i++) {
        if(i % 16 == 0) {
            fprintf(stderr,"\n");
        }
        fprintf(stderr,"[%02x]", (unsigned char)buffer[i]);
    }
    fprintf(stderr,"\n");
    return(0);
}

void sf_usage(const char *program)
{
    fprintf(stderr, "Usage: %s <config_file> [--without-daemon | --no-daemon] "
            "[start | stop | restart]\n", program);
}

void sf_parse_daemon_mode_and_action_ex(int argc, char *argv[],
        bool *daemon_mode, char **action, const char *default_action)
{
    int i;

    *daemon_mode = true;
    for (i=2; i<argc; i++) {
        if (strcmp(argv[i], "--without-daemon") == 0 ||
                strcmp(argv[i], "--no-daemon") == 0)
        {
            *daemon_mode = false;
            break;
        }
    }

    if (argc - (*daemon_mode ? 0 : 1) > 2) {
        *action = argv[argc - 1];
    } else {
        *action = (char *)default_action;
    }
}

int sf_logger_init(LogContext *pContext, const char *filename_prefix)
{
    int result;
    if ((result=log_init_ex(pContext)) != 0) {
        return result;
    }

    if ((result=log_set_prefix_ex(pContext, g_sf_global_vars.base_path,
                    filename_prefix)) != 0)
    {
        return result;
    }

    log_set_rotate_time_format(pContext, "%Y%m%d");
    log_set_cache_ex(pContext, true);
    return 0;
}

ScheduleEntry *sf_logger_set_schedule_entry(struct log_context *pContext,
        ScheduleEntry *pScheduleEntry)
{
    pScheduleEntry->id = sched_generate_next_id();
    pScheduleEntry->time_base.hour = TIME_NONE;
    pScheduleEntry->time_base.minute = TIME_NONE;
    pScheduleEntry->interval = g_sf_global_vars.sync_log_buff_interval;
    pScheduleEntry->task_func = log_sync_func;
    pScheduleEntry->func_args = pContext;
    pScheduleEntry++;

    pScheduleEntry->id = sched_generate_next_id();
    pScheduleEntry->time_base.hour = 0;
    pScheduleEntry->time_base.minute = 0;
    pScheduleEntry->time_base.second = 0;
    pScheduleEntry->interval = 86400;
    pScheduleEntry->task_func = log_notify_rotate;
    pScheduleEntry->func_args = pContext;
    pScheduleEntry++;

    if (g_sf_global_vars.log_file_keep_days > 0) {
        log_set_keep_days(pContext, g_sf_global_vars.log_file_keep_days);

        pScheduleEntry->id = sched_generate_next_id();
        pScheduleEntry->time_base.hour = 1;
        pScheduleEntry->time_base.minute = 30;
        pScheduleEntry->time_base.second = 0;
        pScheduleEntry->interval = 86400;
        pScheduleEntry->task_func = log_delete_old_files;
        pScheduleEntry->func_args = pContext;
        pScheduleEntry++;
    }

    return pScheduleEntry;
}
