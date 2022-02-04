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
    int bytes;
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

    iob = iova->iov;
    bytes = iob->iov_len;
    while (bytes < consume_len) {
        ++iob;
        bytes += iob->iov_len;
    }
    if (bytes == consume_len) {
        ++iob;
        if (iob < (iova->iov + iova->cnt)) {
            bytes += iob->iov_len;
        }
    }

    iova->cnt -= (iob - iova->iov);
    iova->iov = iob;
    if (iova->cnt == 0) {
        struct iovec *last;

        last = iob - 1;
        last->iov_base = (char *)last->iov_base + last->iov_len;
        last->iov_len = 0;
    } else {
        /* adjust the first element */
        remain_len = bytes - consume_len;
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
    int bytes;
    int exceed_len;

    bytes = 0;
    end = iova->ptr + iova->input.cnt;
    for (iob=iova->iov; iob<end; iob++) {
        bytes += iob->iov_len;
        if (bytes > slice_len) {
            exceed_len = bytes - slice_len;
            iob->iov_len -= exceed_len;
            break;
        } else if (bytes == slice_len) {
            break;
        }
    }

    if (iob < end) {
        iova->cnt = (iob - iova->iov) + 1;
        return 0;
    } else {
        logError("file: "__FILE__", line: %d, "
                "iov remain bytes: %d < slice length: %d",
                __LINE__, bytes, slice_len);
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
