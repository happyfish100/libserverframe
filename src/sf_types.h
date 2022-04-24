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

//sf_types.h

#ifndef _SF_TYPES_H_
#define _SF_TYPES_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "fastcommon/connection_pool.h"
#include "fastcommon/fast_task_queue.h"
#include "fastcommon/server_id_func.h"

#define SF_ERROR_INFO_SIZE   256
#define SF_CLUSTER_CONFIG_SIGN_LEN  16

#define SF_SERVER_TASK_TYPE_NONE                 0
#define SF_SERVER_TASK_TYPE_CHANNEL_HOLDER     101   //for request idempotency
#define SF_SERVER_TASK_TYPE_CHANNEL_USER       102   //for request idempotency

typedef void (*sf_accept_done_callback)(struct fast_task_info *task,
        const bool bInnerPort);
typedef int (*sf_set_body_length_callback)(struct fast_task_info *task);
typedef int (*sf_deal_task_func)(struct fast_task_info *task, const int stage);
typedef int (*sf_recv_timeout_callback)(struct fast_task_info *task);

/* calback for release iovec buffer */
typedef void (*sf_release_buffer_callback)(struct fast_task_info *task);

typedef int (*sf_error_handler_callback)(const int errnum);

typedef struct sf_context {
    char name[64];
    struct nio_thread_data *thread_data;
    volatile int thread_count;
    int outer_sock;
    int inner_sock;

    int outer_port;
    int inner_port;
    int accept_threads;
    int work_threads;

    char inner_bind_addr[IP_ADDRESS_SIZE];
    char outer_bind_addr[IP_ADDRESS_SIZE];

    int header_size;
    bool remove_from_ready_list;
    bool realloc_task_buffer;
    sf_deal_task_func deal_task;
    sf_set_body_length_callback set_body_length;
    sf_accept_done_callback accept_done_func;
    TaskCleanUpCallback task_cleanup_func;
    sf_recv_timeout_callback timeout_callback;
    sf_release_buffer_callback release_buffer_callback;
} SFContext;

typedef struct {
    int body_len;      //body length
    short flags;
    volatile short status;
    unsigned char cmd; //command
} SFHeaderInfo;

typedef struct {
    SFHeaderInfo header;
    char *body;
} SFRequestInfo;

typedef struct {
    int length;
    char message[SF_ERROR_INFO_SIZE];
} SFErrorInfo;

typedef struct {
    SFHeaderInfo header;
    SFErrorInfo error;
} SFResponseInfo;

typedef struct {
    int64_t req_start_time;  //unit: microsecond (us)
    SFRequestInfo request;
    SFResponseInfo response;
    bool response_done;
    char log_level;   //level for error log
    bool need_response;
} SFCommonTaskContext;

typedef struct sf_binlog_file_position {
    int index;      //current binlog file
    int64_t offset; //current file offset
} SFBinlogFilePosition;

typedef struct server_binlog_buffer {
    char *buff;    //the buffer pointer
    char *current; //for the consumer
    char *end;     //data end ptr
    int size;      //the buffer size (capacity)
} SFBinlogBuffer;

typedef struct sf_space_stat {
    int64_t total;
    int64_t avail;
    int64_t used;
} SFSpaceStat;

typedef struct sf_binlog_writer_stat {
    int64_t total_count;
    int64_t next_version;
    int waiting_count;
    int max_waitings;
} SFBinlogWriterStat;

typedef struct sf_version_range {
    int64_t first; //including
    int64_t last;  //including
} SFVersionRange;

typedef struct sf_log_config {
    int sync_log_buff_interval; //sync log buff to disk every interval seconds
    bool rotate_everyday;
    bool compress_old;
    int compress_days_before;
    TimeInfo rotate_time;
    TimeInfo delete_old_time;
    int keep_days;
    int64_t rotate_on_size;
} SFLogConfig;

typedef struct sf_slow_log_config {
    bool enabled;
    int log_slower_than_ms;
    char filename_prefix[64];
    SFLogConfig log_cfg;
} SFSlowLogConfig;

typedef struct sf_slow_log_context {
    SFSlowLogConfig cfg;
    LogContext ctx;
} SFSlowLogContext;

typedef enum sf_data_read_rule {
    sf_data_read_rule_any_available,
    sf_data_read_rule_slave_first,
    sf_data_read_rule_master_only
} SFDataReadRule;

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

typedef struct sf_client_common_config {
    SFDataReadRule read_rule;  //the rule for read
    int connect_timeout;
    int network_timeout;
    SFNetRetryConfig net_retry_cfg;
} SFClientCommonConfig;

struct sf_cm_server_entry;
struct sf_cm_server_ptr_array;
typedef struct sf_connection_parameters {
    int buffer_size;
    struct {
        struct sf_cm_server_entry *sentry;
        struct sf_cm_server_ptr_array *old_alives;
    } cm;  //for connection manager
    struct idempotency_client_channel *channel;
} SFConnectionParameters;

typedef struct sf_key_value_array {
    key_value_pair_t *elts;
    int count;
    int alloc;
} SFKeyValueArray;

typedef struct sf_cmd_option {
    string_t name;
    int val;
    bool has_arg;
    const char *desc;
} SFCMDOption;

typedef struct sf_memory_watermark {
    int64_t low;
    int64_t high;
} SFMemoryWatermark;

typedef struct sf_list_limit_info {
    int offset;
    int count;
} SFListLimitInfo;

typedef enum sf_server_group_index_type {
    sf_server_group_index_type_cluster = 1,
    sf_server_group_index_type_service
} SFServerGroupIndexType;

typedef struct sf_cluster_config {
    FCServerConfig server_cfg;
    unsigned char md5_digest[SF_CLUSTER_CONFIG_SIGN_LEN];
    int cluster_group_index;
    int service_group_index;
} SFClusterConfig;

typedef struct sf_synchronize_context {
    pthread_lock_cond_pair_t lcp;
    union {
        bool finished;
        int result;
        int waiting_count;
    };
} SFSynchronizeContext;

typedef enum sf_election_quorum {
    sf_election_quorum_auto,
    sf_election_quorum_any,
    sf_election_quorum_majority,
} SFElectionQuorum;

#endif
