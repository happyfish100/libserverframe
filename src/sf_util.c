
#ifdef OS_LINUX
#include <sys/syscall.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
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

void sf_parse_daemon_mode_and_action(int argc, char *argv[],
        bool *daemon_mode, char **action)
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
        *action = NULL;
    }
}
