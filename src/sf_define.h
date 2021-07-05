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

//sf_define.h

#ifndef _SF_DEFINE_H_
#define _SF_DEFINE_H_

#include "fastcommon/sockopt.h"

#define SF_DEFAULT_CONNECT_TIMEOUT    2
#define SF_DEFAULT_NETWORK_TIMEOUT   10

#define SF_DEF_THREAD_STACK_SIZE  (256 * 1024)
#define SF_MIN_THREAD_STACK_SIZE  (64 * 1024)
#define SF_MAX_THREAD_STACK_SIZE  (2 * 1024 * 1024 * 1024LL)
#define SF_DEF_MAX_PACKAGE_SIZE   (256 * 1024)
#define SF_DEF_MIN_BUFF_SIZE      (64 * 1024)
#define SF_DEF_MAX_BUFF_SIZE      (256 * 1024)
#define SF_MAX_NETWORK_BUFF_SIZE  (2 * 1024 * 1024 * 1024LL)
#define SF_DEF_SYNC_LOG_BUFF_INTERVAL  1

#define SF_NIO_STAGE_NONE        0
#define SF_NIO_STAGE_INIT        1  //set ioevent
#define SF_NIO_STAGE_CONNECT     2  //do connect  (client only)
#define SF_NIO_STAGE_HANDSHAKE   3  //notify the thread to handshake (client only)
#define SF_NIO_STAGE_RECV        4  //do recv
#define SF_NIO_STAGE_SEND        5  //do send
#define SF_NIO_STAGE_FORWARDED   6  //deal the forwarded request
#define SF_NIO_STAGE_CONTINUE    7  //notify the thread continue deal
#define SF_NIO_STAGE_CLOSE     127  //cleanup the task

#define SF_NIO_TASK_STAGE_FETCH(task)  task->nio_stages.current

#define SF_SESSION_ERROR_NOT_EXIST           9992
#define SF_CLUSTER_ERROR_NOT_LEADER          9996
#define SF_CLUSTER_ERROR_LEADER_VERSION_INCONSISTENT 9997
#define SF_CLUSTER_ERROR_BINLOG_INCONSISTENT 9998
#define SF_CLUSTER_ERROR_LEADER_INCONSISTENT 9999
#define SF_CLUSTER_ERROR_MASTER_INCONSISTENT SF_CLUSTER_ERROR_LEADER_INCONSISTENT


#define SF_RETRIABLE_ERROR_MIN             9901
#define SF_RETRIABLE_ERROR_MAX             9988
#define SF_RETRIABLE_ERROR_NO_SERVER       9901  //no server available
#define SF_RETRIABLE_ERROR_NOT_MASTER      9912  //i am not master
#define SF_RETRIABLE_ERROR_NOT_ACTIVE      9913  //i am not active
#define SF_RETRIABLE_ERROR_NO_CHANNEL      9914
#define SF_RETRIABLE_ERROR_CHANNEL_INVALID 9915  //client should re-setup channel

//std errno wrapper for crossing platform
#define SF_ERROR_EBUSY        8816
#define SF_ERROR_EINVAL       8822
#define SF_ERROR_EAGAIN       8835
#define SF_ERROR_EOVERFLOW    8884
#define SF_ERROR_EOPNOTSUPP   8895
#define SF_ERROR_ENODATA      8861

#define SF_FORCE_CLOSE_CONNECTION_ERROR_MIN  SF_RETRIABLE_ERROR_NOT_MASTER
#define SF_FORCE_CLOSE_CONNECTION_ERROR_MAX  SF_RETRIABLE_ERROR_MAX

#define SF_IS_SERVER_RETRIABLE_ERROR(code) \
    ((code >= SF_RETRIABLE_ERROR_MIN && code <= SF_RETRIABLE_ERROR_MAX) || \
     (code == EAGAIN))

#define SF_IS_RETRIABLE_ERROR(code) \
    ((code >= SF_RETRIABLE_ERROR_MIN && code <= SF_RETRIABLE_ERROR_MAX) || \
     (code == EAGAIN) || is_network_error(code))

#define SF_FORCE_CLOSE_CONNECTION_ERROR(code) \
    ((code >= SF_FORCE_CLOSE_CONNECTION_ERROR_MIN &&  \
      code <= SF_FORCE_CLOSE_CONNECTION_ERROR_MAX) || \
      (result == EINVAL) || (result == EOVERFLOW)  || \
      (result != 0 && is_network_error(code)))

#define SF_UNIX_ERRNO(code, errno_for_overflow) \
    (code < 256 ? code : errno_for_overflow)

#define SF_BINLOG_SOURCE_USER        'U'  //by user call
#define SF_BINLOG_SOURCE_REPLAY      'R'  //by binlog replay

#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif

#endif
