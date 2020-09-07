//sf_define.h

#ifndef _SF_DEFINE_H_
#define _SF_DEFINE_H_

#include "fastcommon/common_define.h"

#define SF_DEF_THREAD_STACK_SIZE (64 * 1024)
#define SF_DEF_MAX_PACKAGE_SIZE  (16 * 1024)
#define SF_DEF_MIN_BUFF_SIZE  (64 * 1024)
#define SF_DEF_MAX_BUFF_SIZE  (64 * 1024)

#define SF_NIO_STAGE_INIT       0  //set ioevent
#define SF_NIO_STAGE_CONNECT    1  //do connect  (client only)
#define SF_NIO_STAGE_HANDSHAKE  2  //notify the thread to handshake (client only)
#define SF_NIO_STAGE_RECV       3  //do recv
#define SF_NIO_STAGE_SEND       4  //do send
#define SF_NIO_STAGE_FORWARDED  5  //deal the forwarded request
#define SF_NIO_STAGE_CONTINUE   6  //notify the thread continue deal
#define SF_NIO_STAGE_CLOSE      9  //cleanup the task

#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif

#endif

