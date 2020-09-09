//sf_define.h

#ifndef _SF_DEFINE_H_
#define _SF_DEFINE_H_

#include "fastcommon/common_define.h"

#define SF_DEF_THREAD_STACK_SIZE (64 * 1024)
#define SF_DEF_MAX_PACKAGE_SIZE  (16 * 1024)
#define SF_DEF_MIN_BUFF_SIZE  (64 * 1024)
#define SF_DEF_MAX_BUFF_SIZE  (64 * 1024)

#define SF_NIO_STAGE_INIT        0  //set ioevent
#define SF_NIO_STAGE_CONNECT     1  //do connect  (client only)
#define SF_NIO_STAGE_HANDSHAKE   2  //notify the thread to handshake (client only)
#define SF_NIO_STAGE_RECV        4  //do recv
#define SF_NIO_STAGE_SEND        8  //do send
#define SF_NIO_STAGE_FORWARDED  16  //deal the forwarded request
#define SF_NIO_STAGE_CONTINUE   32  //notify the thread continue deal
#define SF_NIO_STAGE_CLOSE     256  //cleanup the task

#define SF_NIO_FLAG_INPROGRESS        1024
#define SF_NIO_STAGE_FLAGS            (SF_NIO_FLAG_INPROGRESS)
#define SF_NIO_STAGE_RECV_INPROGRESS  (SF_NIO_STAGE_RECV | SF_NIO_FLAG_INPROGRESS)
#define SF_NIO_STAGE_SEND_INPROGRESS  (SF_NIO_STAGE_SEND | SF_NIO_FLAG_INPROGRESS)

#define SF_NIO_TASK_STAGE_FETCH(task)  __sync_add_and_fetch(&task->nio_stage, 0)
#define SF_NIO_STAGE_ONLY(stage)       (stage & (~SF_NIO_STAGE_FLAGS))

#define SF_NIO_STAGE_IS_INPROGRESS(stage)  \
    ((stage & SF_NIO_FLAG_INPROGRESS) != 0)

#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif

#endif

