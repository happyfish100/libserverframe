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

#include "fastcommon/logger.h"
#include "fastcommon/sockopt.h"
#include "sf_define.h"
#include "sf_iov.h"

int sf_iova_consume(SFDynamicIOVArray *iova, const int consume_len)
{
    struct iovec *iob;
    struct iovec *end;
    int sum_bytes;
    int remain_len;
    int result;

    if (iova->cnt <= 0) {
        logError("file: "__FILE__", line: %d, "
                "invalid iov count: %d", __LINE__, iova->cnt);
        return EINVAL;
    }

    if ((result=sf_iova_check_alloc(iova)) != 0) {
        return result;
    }

    end = iova->iov + iova->cnt;
    iob = iova->iov;
    sum_bytes = iob->iov_len;
    for (iob=iob + 1; sum_bytes <= consume_len && iob < end; iob++) {
        sum_bytes += iob->iov_len;
    }

    if (sum_bytes < consume_len) {
        logError("file: "__FILE__", line: %d, "
                "iov length: %d < consume length: %d",
                __LINE__, sum_bytes, consume_len);
        return EOVERFLOW;
    }

    iova->cnt -= (iob - iova->iov);
    iova->iov = iob;
    if (iova->cnt == 0) {
        struct iovec *last;

        /* update the last iov for next slice */
        last = iob - 1;
        last->iov_base = (char *)last->iov_base + last->iov_len;
        last->iov_len = 0;
    } else {
        /* adjust the first element */
        remain_len = sum_bytes - consume_len;
        if (remain_len < iob->iov_len) {
            iob->iov_base = (char *)iob->iov_base +
                (iob->iov_len - remain_len);
            iob->iov_len = remain_len;
        }
    }

    return 0;
}

static inline int iova_slice(SFDynamicIOVArray *iova, const int slice_len)
{
    struct iovec *iob;
    struct iovec *end;
    int sum_bytes;
    int exceed_len;

    sum_bytes = 0;
    end = iova->ptr + iova->input.cnt;
    for (iob=iova->iov; iob<end; iob++) {
        sum_bytes += iob->iov_len;
        if (sum_bytes > slice_len) {
            exceed_len = sum_bytes - slice_len;
            iob->iov_len -= exceed_len;
            break;
        } else if (sum_bytes == slice_len) {
            break;
        }
    }

    if (iob < end) {
        iova->cnt = (iob - iova->iov) + 1;
        return 0;
    } else {
        logError("file: "__FILE__", line: %d, "
                "iov remain bytes: %d < slice length: %d",
                __LINE__, sum_bytes, slice_len);
        iova->cnt = 0;
        return EOVERFLOW;
    }
}

int sf_iova_first_slice(SFDynamicIOVArray *iova, const int slice_len)
{
    int result;

    if ((result=sf_iova_check_alloc(iova)) != 0) {
        return result;
    }

    return iova_slice(iova, slice_len);
}

int sf_iova_next_slice(SFDynamicIOVArray *iova,
        const int consume_len, const int slice_len)
{
    struct iovec *last;
    const struct iovec *origin;
    int remain_len;
    int result;

    if ((result=sf_iova_consume(iova, consume_len)) != 0) {
        return result;
    }

    last = iova->iov + iova->cnt - 1;
    origin = iova->input.iov + (last - iova->ptr);
    remain_len = ((char *)origin->iov_base + origin->iov_len) -
        (char *)last->iov_base;
    if (last->iov_len != remain_len) {
        last->iov_len = remain_len;
        if (iova->cnt == 0) {
            iova->iov = last;
        }
    }

    return iova_slice(iova, slice_len);
}

int sf_iova_memset_ex(const struct iovec *iov, const int iovcnt,
        int c, const int offset, const int length)
{
    const struct iovec *iob;
    const struct iovec *end;
    int sum_bytes;
    int remain_len;
    int left_bytes;
    char *start;

    if (length == 0) {
        return 0;
    }

    sum_bytes = 0;
    end = iov + iovcnt;
    for (iob=iov; iob<end; iob++) {
        sum_bytes += iob->iov_len;
        if (sum_bytes > offset) {
            break;
        }
    }

    if (iob == end) {
        logError("file: "__FILE__", line: %d, "
                "iov length: %d < (offset: %d + length: %d)",
                __LINE__, sum_bytes, offset, length);
        return EOVERFLOW;
    }

    remain_len = sum_bytes - offset;
    start = (char *)iob->iov_base + (iob->iov_len - remain_len);
    if (length <= remain_len) {
        memset(start, c, length);
        return 0;
    }

    memset(start, c, remain_len);
    left_bytes = length - remain_len;
    while (++iob < end) {
        if (left_bytes <= iob->iov_len) {
            memset(iob->iov_base, c, left_bytes);
            return 0;
        }

        memset(iob->iov_base, c, iob->iov_len);
        left_bytes -= iob->iov_len;
    }

    logError("file: "__FILE__", line: %d, "
            "iov length is too short, overflow bytes: %d",
            __LINE__, left_bytes);
    return EOVERFLOW;
}
