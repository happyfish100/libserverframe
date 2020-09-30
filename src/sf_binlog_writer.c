#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <pthread.h>
#include "fastcommon/logger.h"
#include "fastcommon/sockopt.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/pthread_func.h"
#include "fastcommon/sched_thread.h"
#include "sf_global.h"
#include "sf_func.h"
#include "sf_binlog_writer.h"

#define BINLOG_INDEX_FILENAME  SF_BINLOG_FILE_PREFIX"_index.dat"

#define BINLOG_INDEX_ITEM_CURRENT_WRITE     "current_write"
#define BINLOG_INDEX_ITEM_CURRENT_COMPRESS  "current_compress"

#define GET_BINLOG_FILENAME(writer) \
    sprintf(writer->file.name, "%s/%s/%s"SF_BINLOG_FILE_EXT_FMT,  \
            g_sf_binlog_data_path, writer->cfg.subdir_name, \
            SF_BINLOG_FILE_PREFIX, writer->binlog.index)

char *g_sf_binlog_data_path = NULL;

static int write_to_binlog_index_file(SFBinlogWriterInfo *writer)
{
    char full_filename[PATH_MAX];
    char buff[256];
    int result;
    int len;

    snprintf(full_filename, sizeof(full_filename), "%s/%s/%s",
            g_sf_binlog_data_path, writer->cfg.subdir_name,
            BINLOG_INDEX_FILENAME);

    len = sprintf(buff, "%s=%d\n"
            "%s=%d\n",
            BINLOG_INDEX_ITEM_CURRENT_WRITE,
            writer->binlog.index,
            BINLOG_INDEX_ITEM_CURRENT_COMPRESS,
            writer->binlog.compress_index);
    if ((result=safeWriteToFile(full_filename, buff, len)) != 0) {
        logError("file: "__FILE__", line: %d, "
            "write to file \"%s\" fail, "
            "errno: %d, error info: %s",
            __LINE__, full_filename,
            result, STRERROR(result));
    }

    return result;
}

static int get_binlog_index_from_file(SFBinlogWriterInfo *writer)
{
    char full_filename[PATH_MAX];
    IniContext ini_context;
    int result;

    snprintf(full_filename, sizeof(full_filename), "%s/%s/%s",
            g_sf_binlog_data_path, writer->cfg.subdir_name,
            BINLOG_INDEX_FILENAME);
    if (access(full_filename, F_OK) != 0) {
        if (errno == ENOENT) {
            writer->binlog.index = 0;
            return write_to_binlog_index_file(writer);
        }
    }

    if ((result=iniLoadFromFile(full_filename, &ini_context)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "load from file \"%s\" fail, error code: %d",
                __LINE__, full_filename, result);
        return result;
    }

    writer->binlog.index = iniGetIntValue(NULL,
            BINLOG_INDEX_ITEM_CURRENT_WRITE, &ini_context, 0);
    writer->binlog.compress_index = iniGetIntValue(NULL,
            BINLOG_INDEX_ITEM_CURRENT_COMPRESS, &ini_context, 0);

    iniFreeContext(&ini_context);
    return 0;
}

static int open_writable_binlog(SFBinlogWriterInfo *writer)
{
    if (writer->file.fd >= 0) {
        close(writer->file.fd);
    }

    GET_BINLOG_FILENAME(writer);
    writer->file.fd = open(writer->file.name,
            O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (writer->file.fd < 0) {
        logError("file: "__FILE__", line: %d, "
                "open file \"%s\" fail, "
                "errno: %d, error info: %s",
                __LINE__, writer->file.name,
                errno, STRERROR(errno));
        return errno != 0 ? errno : EACCES;
    }

    writer->file.size = lseek(writer->file.fd, 0, SEEK_END);
    if (writer->file.size < 0) {
        logError("file: "__FILE__", line: %d, "
                "lseek file \"%s\" fail, "
                "errno: %d, error info: %s",
                __LINE__, writer->file.name,
                errno, STRERROR(errno));
        return errno != 0 ? errno : EIO;
    }

    return 0;
}

static int open_next_binlog(SFBinlogWriterInfo *writer)
{
    GET_BINLOG_FILENAME(writer);
    if (access(writer->file.name, F_OK) == 0) {
        char bak_filename[PATH_MAX];
        char date_str[32];

        sprintf(bak_filename, "%s.%s", writer->file.name,
                formatDatetime(g_current_time, "%Y%m%d%H%M%S",
                    date_str, sizeof(date_str)));
        if (rename(writer->file.name, bak_filename) == 0) {
            logWarning("file: "__FILE__", line: %d, "
                    "binlog file %s exist, rename to %s",
                    __LINE__, writer->file.name, bak_filename);
        } else {
            logError("file: "__FILE__", line: %d, "
                    "rename binlog %s to backup %s fail, "
                    "errno: %d, error info: %s",
                    __LINE__, writer->file.name, bak_filename,
                    errno, STRERROR(errno));
            return errno != 0 ? errno : EPERM;
        }
    }

    return open_writable_binlog(writer);
}

static int do_write_to_file(SFBinlogWriterInfo *writer,
        char *buff, const int len)
{
    int result;

    if (fc_safe_write(writer->file.fd, buff, len) != len) {
        result = errno != 0 ? errno : EIO;
        logError("file: "__FILE__", line: %d, "
                "write to binlog file \"%s\" fail, "
                "errno: %d, error info: %s",
                __LINE__, writer->file.name,
                result, STRERROR(result));
        return result;
    }

    if (fsync(writer->file.fd) != 0) {
        result = errno != 0 ? errno : EIO;
        logError("file: "__FILE__", line: %d, "
                "fsync to binlog file \"%s\" fail, "
                "errno: %d, error info: %s",
                __LINE__, writer->file.name,
                result, STRERROR(result));
        return result;
    }

    writer->file.size += len;
    return 0;
}

static int check_write_to_file(SFBinlogWriterInfo *writer,
        char *buff, const int len)
{
    int result;

    if (writer->file.size + len <= SF_BINLOG_FILE_MAX_SIZE) {
        return do_write_to_file(writer, buff, len);
    }

    writer->binlog.index++;  //binlog rotate
    if ((result=write_to_binlog_index_file(writer)) == 0) {
        result = open_next_binlog(writer);
    }

    if (result != 0) {
        logError("file: "__FILE__", line: %d, "
                "open binlog file \"%s\" fail",
                __LINE__, writer->file.name);
        return result;
    }

    return do_write_to_file(writer, buff, len);
}

static int binlog_write_to_file(SFBinlogWriterInfo *writer)
{
    int result;
    int len;

    len = SF_BINLOG_BUFFER_LENGTH(writer->binlog_buffer);
    if (len == 0) {
        return 0;
    }

    result = check_write_to_file(writer, writer->binlog_buffer.buff, len);
    writer->binlog_buffer.end = writer->binlog_buffer.buff;
    return result;
}

int sf_binlog_get_current_write_index(SFBinlogWriterInfo *writer)
{
    if (writer == NULL) {   //for data recovery
        return 0;
    }

    if (writer->binlog.index < 0) {
        get_binlog_index_from_file(writer);
    }

    return writer->binlog.index;
}

void sf_binlog_get_current_write_position(SFBinlogWriterInfo *writer,
        SFBinlogFilePosition *position)
{
    position->index = writer->binlog.index;
    position->offset = writer->file.size;
}

static inline void binlog_writer_set_next_version(SFBinlogWriterInfo *writer,
        const uint64_t next_version)
{
    writer->version_ctx.next = next_version;
    writer->version_ctx.ring.start = writer->version_ctx.ring.end =
        writer->version_ctx.ring.entries + next_version %
        writer->version_ctx.ring.size;
}

static inline int deal_binlog_one_record(SFBinlogWriterBuffer *wb)
{
    int result;

    if (wb->bf.length >= wb->writer->binlog_buffer.size / 4) {
        if (SF_BINLOG_BUFFER_LENGTH(wb->writer->binlog_buffer) > 0) {
            if ((result=binlog_write_to_file(wb->writer)) != 0) {
                return result;
            }
        }

        return check_write_to_file(wb->writer,
                wb->bf.buff, wb->bf.length);
    }

    if (wb->writer->file.size + SF_BINLOG_BUFFER_LENGTH(wb->writer->
                binlog_buffer) + wb->bf.length > SF_BINLOG_FILE_MAX_SIZE)
    {
        if ((result=binlog_write_to_file(wb->writer)) != 0) {
            return result;
        }
    } else if (wb->writer->binlog_buffer.size - SF_BINLOG_BUFFER_LENGTH(
                wb->writer->binlog_buffer) < wb->bf.length)
    {
        if ((result=binlog_write_to_file(wb->writer)) != 0) {
            return result;
        }
    }

    memcpy(wb->writer->binlog_buffer.end,
            wb->bf.buff, wb->bf.length);
    wb->writer->binlog_buffer.end += wb->bf.length;
    return 0;
}

static void repush_to_queue(SFBinlogWriterThread *thread, SFBinlogWriterBuffer *wb)
{
    SFBinlogWriterBuffer *previous;
    SFBinlogWriterBuffer *current;

    PTHREAD_MUTEX_LOCK(&thread->queue.lc_pair.lock);
    if (thread->queue.head == NULL) {
        wb->next = NULL;
        thread->queue.head = thread->queue.tail = wb;
    } else if (wb->version <= ((SFBinlogWriterBuffer *)
                thread->queue.head)->version)
    {
        wb->next = thread->queue.head;
        thread->queue.head = wb;
    } else if (wb->version > ((SFBinlogWriterBuffer *)
                thread->queue.tail)->version)
    {
        wb->next = NULL;
        ((SFBinlogWriterBuffer *)thread->queue.tail)->next = wb;
        thread->queue.tail = wb;
    } else {
        previous = thread->queue.head;
        current = ((SFBinlogWriterBuffer *)thread->queue.head)->next;
        while (current != NULL && wb->version > current->version) {
            previous = current;
            current = current->next;
        }

        wb->next = previous->next;
        previous->next = wb;
    }
    PTHREAD_MUTEX_UNLOCK(&thread->queue.lc_pair.lock);
}

#define DEAL_CURRENT_VERSION_WBUFFER(writer, wb) \
    do {  \
        if ((result=deal_binlog_one_record(wb)) != 0) {  \
            return result;  \
        } \
        fast_mblock_free_object(&writer->thread->mblock, wb);  \
        ++writer->version_ctx.next;  \
    } while (0)

static int deal_record_by_version(SFBinlogWriterBuffer *wb)
{
    SFBinlogWriterInfo *writer;
    SFBinlogWriterBuffer **current;
    int64_t distance;
    int result;
    int index;
    bool expand;

    writer = wb->writer;
    distance = wb->version - writer->version_ctx.next;
    if (distance >= (writer->version_ctx.ring.size - 1)) {
        logWarning("file: "__FILE__", line: %d, "
                "current version: %"PRId64" is too large, "
                "exceeds %"PRId64" + %d", __LINE__,
                wb->version, writer->version_ctx.next,
                writer->version_ctx.ring.size - 1);
        repush_to_queue(writer->thread, wb);
        fc_sleep_ms(10);
        return 0;
    }

    /*
    logInfo("%s wb version===== %"PRId64", next: %"PRId64", writer: %p",
            writer->cfg.subdir_name, wb->version,
            writer->version_ctx.next, writer);
            */

    current = writer->version_ctx.ring.entries + wb->version %
        writer->version_ctx.ring.size;
    if (current == writer->version_ctx.ring.start) {
        DEAL_CURRENT_VERSION_WBUFFER(writer, wb);

        index = writer->version_ctx.ring.start - writer->version_ctx.ring.entries;
        if (writer->version_ctx.ring.start == writer->version_ctx.ring.end) {
            writer->version_ctx.ring.start = writer->version_ctx.ring.end =
                writer->version_ctx.ring.entries +
                (++index) % writer->version_ctx.ring.size;
            return 0;
        }

        writer->version_ctx.ring.start = writer->version_ctx.ring.entries +
            (++index) % writer->version_ctx.ring.size;
        while (writer->version_ctx.ring.start != writer->version_ctx.ring.end &&
                *(writer->version_ctx.ring.start) != NULL)
        {
            DEAL_CURRENT_VERSION_WBUFFER(writer, *(writer->version_ctx.ring.start));
            *(writer->version_ctx.ring.start) = NULL;

            writer->version_ctx.ring.start = writer->version_ctx.ring.entries +
                (++index) % writer->version_ctx.ring.size;
            writer->version_ctx.ring.count--;
        }
        return 0;
    }

    *current = wb;
    writer->version_ctx.ring.count++;

    if (writer->version_ctx.ring.count > writer->version_ctx.ring.max_count) {
        writer->version_ctx.ring.max_count = writer->version_ctx.ring.count;
        logDebug("%s max ring.count ==== %d", writer->cfg.subdir_name,
                writer->version_ctx.ring.count);
    }

    if (writer->version_ctx.ring.start == writer->version_ctx.ring.end) { //empty
        expand = true;
    } else if (writer->version_ctx.ring.end > writer->version_ctx.ring.start) {
        expand = !(current > writer->version_ctx.ring.start &&
                current < writer->version_ctx.ring.end);
    } else {
        expand = (current >= writer->version_ctx.ring.end &&
                current < writer->version_ctx.ring.start);
    }

    if (expand) {
        writer->version_ctx.ring.end = writer->version_ctx.ring.entries +
            (wb->version + 1) % writer->version_ctx.ring.size;
    }

    return 0;
}

static inline void add_to_flush_writer_array(SFBinlogWriterThread *thread,
        SFBinlogWriterInfo *writer)
{
    struct sf_binlog_writer_info **entry;
    struct sf_binlog_writer_info **end;

    if (thread->flush_writers.count == 0) {
        thread->flush_writers.entries[thread->flush_writers.count++] = writer;
        return;
    }

    if (thread->flush_writers.count == thread->flush_writers.alloc) {
        return;
    }
    if (thread->flush_writers.entries[0] == writer) {
        return;
    }

    end = thread->flush_writers.entries + thread->flush_writers.count;
    for (entry=thread->flush_writers.entries+1; entry<end; entry++) {
        if (*entry == writer) {
            return;
        }
    }

    thread->flush_writers.entries[thread->flush_writers.count++] = writer;
}

static inline int flush_writer_files(SFBinlogWriterThread *thread)
{
    struct sf_binlog_writer_info **entry;
    struct sf_binlog_writer_info **end;
    int result;

    //logInfo("flush_writers count: %d", thread->flush_writers.count);
    if (thread->flush_writers.count == 1) {
        /*
        logInfo("flush_writers filename: %s",
                thread->flush_writers.entries[0]->file.name);
                */
        return binlog_write_to_file(thread->flush_writers.entries[0]);
    }

    end = thread->flush_writers.entries + thread->flush_writers.count;
    for (entry=thread->flush_writers.entries; entry<end; entry++) {
        if ((result=binlog_write_to_file(*entry)) != 0) {
            return result;
        }
    }

    return 0;
}

static int deal_binlog_records(SFBinlogWriterThread *thread,
        SFBinlogWriterBuffer *wb_head)
{
    int result;
    SFBinlogWriterBuffer *wbuffer;
    SFBinlogWriterBuffer *current;

    thread->flush_writers.count = 0;
    wbuffer = wb_head;

    if (thread->order_by == SF_BINLOG_THREAD_TYPE_ORDER_BY_VERSION) {
        do {
            current = wbuffer;
            wbuffer = wbuffer->next;

            if (current->type == SF_BINLOG_BUFFER_TYPE_SET_NEXT_VERSION) {
                if (current->writer->version_ctx.ring.start !=
                        current->writer->version_ctx.ring.end)
                {
                    logWarning("file: "__FILE__", line: %d, "
                            "subdir_name: %s, ring not empty, "
                            "maybe some mistake happen", __LINE__,
                            current->writer->cfg.subdir_name);
                }

                logDebug("file: "__FILE__", line: %d, "
                        "subdir_name: %s, set next version to %"PRId64,
                        __LINE__, current->writer->cfg.subdir_name,
                        current->version);

                binlog_writer_set_next_version(current->writer,
                        current->version);
                fast_mblock_free_object(&current->writer->
                        thread->mblock, current);
            } else {
                add_to_flush_writer_array(thread, current->writer);
                if ((result=deal_record_by_version(current)) != 0) {
                    return result;
                }
            }
        } while (wbuffer != NULL);
    } else {
        do {
            if ((result=deal_binlog_one_record(wbuffer)) != 0) {
                return result;
            }

            current = wbuffer;
            wbuffer = wbuffer->next;

            add_to_flush_writer_array(thread, current->writer);
            fast_mblock_free_object(&current->writer->
                    thread->mblock, current);
        } while (wbuffer != NULL);
    }

    return flush_writer_files(thread);
}

void sf_binlog_writer_finish(SFBinlogWriterInfo *writer)
{
    SFBinlogWriterBuffer *wb_head;
    int count;

    if (writer->file.name != NULL) {
        fc_queue_terminate(&writer->thread->queue);

        count = 0;
        while (writer->thread->running && ++count < 300) {
            fc_sleep_ms(10);
        }
        
        if (writer->thread->running) {
            logWarning("file: "__FILE__", line: %d, "
                    "%s binlog write thread still running, "
                    "exit anyway!", __LINE__, writer->cfg.subdir_name);
        }

        wb_head = (SFBinlogWriterBuffer *)fc_queue_try_pop_all(
                &writer->thread->queue);
        if (wb_head != NULL) {
            deal_binlog_records(writer->thread, wb_head);
        }

        free(writer->file.name);
        writer->file.name = NULL;
    }

    if (writer->file.fd >= 0) {
        close(writer->file.fd);
        writer->file.fd = -1;
    }
}

static void *binlog_writer_func(void *arg)
{
    SFBinlogWriterThread *thread;
    SFBinlogWriterBuffer *wb_head;

    thread = (SFBinlogWriterThread *)arg;
    thread->running = true;
    while (SF_G_CONTINUE_FLAG) {
        wb_head = (SFBinlogWriterBuffer *)fc_queue_pop_all(&thread->queue);
        if (wb_head == NULL) {
            continue;
        }

        if (deal_binlog_records(thread, wb_head) != 0) {
            logCrit("file: "__FILE__", line: %d, "
                    "deal_binlog_records fail, "
                    "program exit!", __LINE__);
            sf_terminate_myself();
        }
    }

    thread->running = false;
    return NULL;
}

static int binlog_wbuffer_alloc_init(void *element, void *args)
{
    SFBinlogWriterBuffer *wbuffer;
    SFBinlogWriterInfo *writer;

    wbuffer = (SFBinlogWriterBuffer *)element;
    writer = (SFBinlogWriterInfo *)args;
    wbuffer->writer = writer;
    wbuffer->bf.alloc_size = writer->cfg.max_record_size;
    if (writer->thread->use_fixed_buffer_size) {
        wbuffer->bf.buff = (char *)(wbuffer + 1);
    } else {
        wbuffer->bf.buff = (char *)fc_malloc(writer->cfg.max_record_size);
        if (wbuffer->bf.buff == NULL) {
            return ENOMEM;
        }
    }
    return 0;
}

int sf_binlog_writer_init_normal(SFBinlogWriterInfo *writer,
        const char *subdir_name, const int buffer_size)
{
    int result;
    int path_len;
    bool create;
    char filepath[PATH_MAX];

    if ((result=sf_binlog_buffer_init(&writer->binlog_buffer,
                    buffer_size)) != 0)
    {
        return result;
    }

    path_len = snprintf(filepath, sizeof(filepath), "%s/%s",
            g_sf_binlog_data_path, subdir_name);
    if ((result=fc_check_mkdir_ex(filepath, 0775, &create)) != 0) {
        return result;
    }
    if (create) {
        SF_CHOWN_RETURN_ON_ERROR(filepath, geteuid(), getegid());
    }

    writer->file.fd = -1;
    snprintf(writer->cfg.subdir_name,
            sizeof(writer->cfg.subdir_name),
            "%s", subdir_name);
    writer->file.name = (char *)fc_malloc(path_len + 32);
    if (writer->file.name == NULL) {
        return ENOMEM;
    }

    if ((result=get_binlog_index_from_file(writer)) != 0) {
        return result;
    }

    if ((result=open_writable_binlog(writer)) != 0) {
        return result;
    }

    return 0;
}

int sf_binlog_writer_init_by_version(SFBinlogWriterInfo *writer,
        const char *subdir_name, const uint64_t next_version,
        const int buffer_size, const int ring_size)
{
    int bytes;

    logDebug("init writer %s ===== next version: %"PRId64", writer: %p",
            subdir_name, next_version, writer);

    bytes = sizeof(SFBinlogWriterBuffer *) * ring_size;
    writer->version_ctx.ring.entries = (SFBinlogWriterBuffer **)fc_malloc(bytes);
    if (writer->version_ctx.ring.entries == NULL) {
        return ENOMEM;
    }
    memset(writer->version_ctx.ring.entries, 0, bytes);
    writer->version_ctx.ring.size = ring_size;
    writer->version_ctx.ring.count = 0;
    writer->version_ctx.ring.max_count = 0;

    binlog_writer_set_next_version(writer, next_version);
    return sf_binlog_writer_init_normal(writer, subdir_name, buffer_size);
}

int sf_binlog_writer_init_thread_ex(SFBinlogWriterThread *thread,
        SFBinlogWriterInfo *writer, const short order_mode,
        const short order_by, const int max_record_size,
        const int writer_count, const bool use_fixed_buffer_size)
{
    const int alloc_elements_once = 1024;
    int element_size;
    pthread_t tid;
    int result;
    int bytes;

    thread->order_mode = order_mode;
    thread->order_by = order_by;
    thread->use_fixed_buffer_size = use_fixed_buffer_size;
    writer->cfg.max_record_size = max_record_size;
    writer->thread = thread;

    element_size = sizeof(SFBinlogWriterBuffer);
    if (use_fixed_buffer_size) {
        element_size += max_record_size;
    }
    if ((result=fast_mblock_init_ex1(&thread->mblock, "binlog_wbuffer",
                     element_size, alloc_elements_once, 0,
                     binlog_wbuffer_alloc_init, writer, true)) != 0)
    {
        return result;
    }

    if ((result=fc_queue_init(&thread->queue, (unsigned long)
                    (&((SFBinlogWriterBuffer *)NULL)->next))) != 0)
    {
        return result;
    }

    bytes = sizeof(struct sf_binlog_writer_info *) * writer_count;
    thread->flush_writers.entries = (struct sf_binlog_writer_info **)fc_malloc(bytes);
    if (thread->flush_writers.entries == NULL) {
        return ENOMEM;
    }
    thread->flush_writers.alloc = writer_count;
    thread->flush_writers.count = 0;

    return fc_create_thread(&tid, binlog_writer_func, thread,
            SF_G_THREAD_STACK_SIZE);
}

int sf_binlog_writer_change_order_by(SFBinlogWriterThread *thread,
        const short order_by)
{
    if (thread->order_by == order_by) {
        return 0;
    }

    if (thread->order_mode != SF_BINLOG_THREAD_ORDER_MODE_VARY) {
        logError("file: "__FILE__", line: %d, "
                "unexpected order mode: %d, can't set "
                "order by to %d!", __LINE__,
                thread->order_mode, order_by);
        return EINVAL;
    }

    thread->order_by = order_by;
    return 0;
}

int sf_binlog_writer_change_next_version(SFBinlogWriterInfo *writer,
        const int64_t next_version)
{
    SFBinlogWriterBuffer *buffer;

    if (writer->thread->order_by != SF_BINLOG_THREAD_TYPE_ORDER_BY_VERSION) {
        logError("file: "__FILE__", line: %d, "
                "unexpected order by type: %d, can't set "
                "next version to %"PRId64"!", __LINE__,
                writer->thread->order_by, next_version);
        return EINVAL;
    }

    if ((buffer=sf_binlog_writer_alloc_versioned_buffer_ex(writer, next_version,
                    SF_BINLOG_BUFFER_TYPE_SET_NEXT_VERSION)) == NULL)
    {
        return ENOMEM;
    }

    fc_queue_push(&writer->thread->queue, buffer);
    return 0;
}

int sf_binlog_writer_set_binlog_index(SFBinlogWriterInfo *writer,
        const int binlog_index)
{
    int result;

    if (writer->binlog.index != binlog_index) {
        writer->binlog.index = binlog_index;
        if ((result=write_to_binlog_index_file(writer)) != 0) {
            return result;
        }
    }

    return open_writable_binlog(writer);
}

int sf_binlog_writer_get_last_lines(const char *subdir_name,
        const int current_write_index, char *buff,
        const int buff_size, int *count, int *length)
{
    int result;
    int remain_count;
    int current_count;
    int current_index;
    int i;
    char filename[PATH_MAX];
    string_t lines;

    current_index = current_write_index;
    *length = 0;
    remain_count = *count;
    for (i=0; i<2; i++) {
        current_count = remain_count;
        sf_binlog_writer_get_filename(subdir_name,
                current_index, filename, sizeof(filename));
        result = fc_get_last_lines(filename, buff + *length,
                buff_size - *length, &lines, &current_count);
        if (result == 0) {
            memmove(buff + *length, lines.str, lines.len);
            *length += lines.len;
            remain_count -= current_count;
            if (remain_count == 0) {
                break;
            }
        } else if (result != ENOENT) {
            *count = 0;
            return result;
        }
        if (current_index == 0) {
            break;
        }

        --current_index;  //try previous binlog file
    }

    *count -= remain_count;
    return 0;
}
