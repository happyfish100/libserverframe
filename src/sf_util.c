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
#include "sf_define.h"
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

void sf_usage_ex(const char *program, const SFCMDOption *other_options)
{
    fprintf(stderr, "\nUsage: %s [options] <config_file> "
            "[start | stop | restart | status]\n\noptions:\n", program);

    if (other_options != NULL) {
        const SFCMDOption *option;
        option = other_options;
        while (option->name.str != NULL) {
            fprintf(stderr, "\t%s\n", option->desc);
            option++;
        }
    }

    fprintf(stderr, "\t-N | --no-daemon: run in foreground\n"
            "\t-V | --version: show version info\n"
            "\t-h | --help: for this usage\n\n");
}

static int match_option(const char *str, const SFCMDOption *option)
{
    const char *start;
    const char *end;

    if (str[1] == '-') {
        start = str + 2;
        while (option->name.str != NULL) {
            if (strncmp(option->name.str, start,
                        option->name.len) == 0)
            {
                end = start + option->name.len;
                if (*end == '\0') {
                    return option->has_arg ? 2 : 1;
                } else if (*end == '=') {
                    return 1;
                }
            }

            option++;
        }
    } else {
        while (option->name.str != NULL) {
            if (option->val == str[1]) {
                if (str[2] == '\0') {
                    return option->has_arg ? 2 : 1;
                } else {
                    return 1;
                }
            }
            option++;
        }
    }

    return 0;
}


const char *sf_parse_daemon_mode_and_action_ex(int argc, char *argv[],
        const Version *version, bool *daemon_mode, char **action,
        const char *default_action, const SFCMDOption *other_options)
{
#define CMD_NORMAL_ARG_COUNT 2
    int i;
    int inc;
    struct {
        int argc;
        char *argv[CMD_NORMAL_ARG_COUNT];
    } normal;
    const char *config_filepath;

    normal.argc = 0;
    *daemon_mode = true;
    i = 1;
    while (i < argc) {
        if (argv[i][0] != '-') {
            if (normal.argc == CMD_NORMAL_ARG_COUNT) {
                fprintf(stderr, "\nError: too many arguments!\n");
                sf_usage_ex(argv[0], other_options);
                return NULL;
            }
            normal.argv[normal.argc++] = argv[i++];
            continue;
        }

        if (other_options != NULL) {
            inc = match_option(argv[i], other_options);
            if (inc > 0) {
                i += inc;
                if (i > argc) {
                    fprintf(stderr, "\nError: expect argument!\n");
                    sf_usage_ex(argv[0], other_options);
                    return NULL;
                }
                continue;
            }
        }

        if (strcmp(argv[i], "-V") == 0 ||
                strcmp(argv[i], "--version") == 0)
        {
            char *last_slash;
            char *proc_name;
            if ((last_slash=strrchr(argv[0], '/')) != NULL) {
                proc_name = last_slash + 1;
            } else {
                proc_name = argv[0];
            }
            printf("\n%s V%d.%d.%d\n\n", proc_name, version->major,
                    version->minor, version->patch);
            return NULL;
        }
        if (strcmp(argv[i], "-h") == 0 ||
                strcmp(argv[i], "--help") == 0)
        {
            sf_usage_ex(argv[0], other_options);
            return NULL;
        }

        if (strcmp(argv[i], "-N") == 0 ||
                strcmp(argv[i], "--no-daemon") == 0)
        {
            *daemon_mode = false;
            i++;
        } else {
            fprintf(stderr, "\nError: unrecognized option: %s\n", argv[i]);
            sf_usage_ex(argv[0], other_options);
            return NULL;
        }
    }

    if (normal.argc == 0) {
        fprintf(stderr, "\nError: expect config file!\n");
        sf_usage_ex(argv[0], other_options);
        return NULL;
    }

    config_filepath = normal.argv[0];
    if (normal.argc > 1) {
        *action = normal.argv[1];
    } else {
        *action = (char *)default_action;
    }

    return config_filepath;
}

void sf_parse_cmd_option_bool(int argc, char *argv[],
        const string_t *short_option, const string_t *long_option,
        bool *value)
{
    char **pp;
    char **end;
    int len;

    *value = false;
    end = argv + argc;
    for (pp=argv + 1; pp<end; pp++) {
        if (**pp != '-') {
            continue;
        }

        len = strlen(*pp);
        if (fc_string_equals2(short_option, *pp, len) ||
                fc_string_equals2(long_option, *pp, len))
        {
            *value = true;
            break;
        }
    }
}

int sf_logger_init(LogContext *pContext, const char *filename_prefix)
{
    int result;
    if ((result=log_init_ex(pContext)) != 0) {
        return result;
    }

    if ((result=log_set_prefix_ex(pContext, SF_G_BASE_PATH_STR,
                    filename_prefix)) != 0)
    {
        return result;
    }

    log_set_rotate_time_format(pContext, "%Y%m%d");
    log_set_cache_ex(pContext, true);
    return 0;
}

ScheduleEntry *sf_logger_set_schedule_entry(struct log_context *pContext,
        SFLogConfig *log_cfg, ScheduleEntry *pScheduleEntry)
{
    INIT_SCHEDULE_ENTRY(*pScheduleEntry, sched_generate_next_id(),
            TIME_NONE, TIME_NONE, 0, log_cfg->sync_log_buff_interval,
            log_sync_func, pContext);
    pScheduleEntry++;

    if (log_cfg->rotate_everyday) {
        INIT_SCHEDULE_ENTRY_EX(*pScheduleEntry, sched_generate_next_id(),
                log_cfg->rotate_time, 86400, log_notify_rotate, pContext);
        pScheduleEntry++;
    }

    if ((log_cfg->rotate_everyday || log_cfg->rotate_on_size > 0) &&
            (log_cfg->keep_days > 0))
    {
        log_set_keep_days(pContext, log_cfg->keep_days);
        INIT_SCHEDULE_ENTRY_EX(*pScheduleEntry, sched_generate_next_id(),
                log_cfg->delete_old_time, 86400, log_delete_old_files,
                pContext);
        pScheduleEntry++;
    }

    return pScheduleEntry;
}

const char *sf_strerror(const int errnum)
{
    switch (errnum) {
        case SF_CLUSTER_ERROR_BINLOG_INCONSISTENT:
            return "binlog inconsistent";
        case SF_CLUSTER_ERROR_LEADER_INCONSISTENT:
            return "leader or master inconsistent";
        case SF_RETRIABLE_ERROR_NO_SERVER:
            return "no server available";
        case SF_RETRIABLE_ERROR_NOT_MASTER:
            return "i am not master";
        case SF_RETRIABLE_ERROR_NOT_ACTIVE:
            return "i am not active";
        case SF_RETRIABLE_ERROR_NO_CHANNEL:
            return "idempotency channel not exist";
        case SF_RETRIABLE_ERROR_CHANNEL_INVALID:
            return "idempotency channel is invalid";
        case SF_ERROR_EINVAL:
            return STRERROR(EINVAL);
        case SF_ERROR_EAGAIN:
            return STRERROR(EAGAIN);
        case SF_ERROR_EOVERFLOW:
            return STRERROR(EOVERFLOW);
        case SF_ERROR_ENODATA:
            return STRERROR(ENODATA);
        default:
            return STRERROR(errnum);
    }
}
