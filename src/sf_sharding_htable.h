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

#ifndef _SF_SHARDING_HTABLE_H
#define _SF_SHARDING_HTABLE_H

#include <limits.h>
#include <sys/types.h>
#include "fastcommon/common_define.h"
#include "fastcommon/fc_list.h"
#include "fastcommon/pthread_func.h"

typedef enum {
    sf_sharding_htable_key_ids_one = 1,
    sf_sharding_htable_key_ids_two = 2
} SFShardingHtableKeyType;

struct sf_sharding_hash_entry;
struct sf_htable_sharding;

typedef int (*sf_sharding_htable_insert_callback)
    (struct sf_sharding_hash_entry *entry, void *arg, const bool new_create);

typedef void *(*sf_sharding_htable_find_callback)
    (struct sf_sharding_hash_entry *entry, void *arg);

typedef bool (*sf_sharding_htable_delete_callback)
    (struct sf_sharding_hash_entry *entry, void *arg);

typedef bool (*sf_sharding_htable_accept_reclaim_callback)
    (struct sf_sharding_hash_entry *entry);

typedef struct sf_two_ids_hash_key {
    union {
        uint64_t id1;
        uint64_t oid;  //object id such as inode
    };

    union {
        uint64_t id2;
        uint64_t tid;  //thread id
        uint64_t bid;  //file block id
    };
} SFTwoIdsHashKey;

typedef struct sf_sharding_hash_entry {
    SFTwoIdsHashKey key;
    struct {
        struct fc_list_head htable;  //for hashtable
        struct fc_list_head lru;     //for LRU chain
    } dlinks;
    int64_t last_update_time_ms;
    struct sf_htable_sharding *sharding;  //hold for lock
} SFShardingHashEntry;

typedef struct sf_dlink_hashtable {
    struct fc_list_head *buckets;
    int64_t capacity;
} SFDlinkHashtable;

struct sf_htable_sharding_context;
typedef struct sf_htable_sharding {
    pthread_mutex_t lock;
    struct fast_mblock_man *allocator;
    struct fc_list_head lru;
    SFDlinkHashtable hashtable;
    int64_t element_count;
    int64_t element_limit;
    volatile int64_t last_reclaim_time_ms;
    struct sf_htable_sharding_context *ctx;
} SFHtableSharding;

typedef struct sf_htable_sharding_array {
    SFHtableSharding *entries;
    int count;
} SFHtableShardingArray;

typedef struct sf_htable_sharding_context {
    struct {
        int64_t min_ttl_ms;
        int64_t max_ttl_ms;
        double elt_ttl_ms;
        int elt_water_mark;  //trigger reclaim when elements exceeds water mark
        bool enabled;
    } sharding_reclaim;

    struct {
        int count;
        struct fast_mblock_man *elts;
    } allocators;  //shared allocators

    SFShardingHtableKeyType key_type;  //id count in the hash entry
    sf_sharding_htable_insert_callback insert_callback;
    sf_sharding_htable_find_callback find_callback;
    sf_sharding_htable_delete_callback delete_callback;
    sf_sharding_htable_accept_reclaim_callback accept_reclaim_callback;
    SFHtableShardingArray sharding_array;
} SFHtableShardingContext;

#ifdef __cplusplus
extern "C" {
#endif

    int sf_sharding_htable_init_ex(SFHtableShardingContext *sharding_ctx,
            const SFShardingHtableKeyType key_type,
            sf_sharding_htable_insert_callback insert_callback,
            sf_sharding_htable_find_callback find_callback,
            sf_sharding_htable_delete_callback delete_callback,
            sf_sharding_htable_accept_reclaim_callback reclaim_callback,
            const int sharding_count, const int64_t htable_capacity,
            const int allocator_count, const int element_size,
            int64_t element_limit, const int64_t min_ttl_ms,
            const int64_t max_ttl_ms, const double low_water_mark_ratio);

    static inline int sf_sharding_htable_init(SFHtableShardingContext
            *sharding_ctx, const SFShardingHtableKeyType key_type,
            sf_sharding_htable_insert_callback insert_callback,
            sf_sharding_htable_find_callback find_callback,
            sf_sharding_htable_delete_callback delete_callback,
            sf_sharding_htable_accept_reclaim_callback reclaim_callback,
            const int sharding_count, const int64_t htable_capacity,
            const int allocator_count, const int element_size,
            int64_t element_limit, const int64_t min_ttl_ms,
            const int64_t max_ttl_ms)
    {
        const double low_water_mark_ratio = 0.10;
        return sf_sharding_htable_init_ex(sharding_ctx, key_type,
                insert_callback, find_callback, delete_callback,
                reclaim_callback, sharding_count, htable_capacity,
                allocator_count, element_size, element_limit,
                min_ttl_ms, max_ttl_ms, low_water_mark_ratio);
    }

    int sf_sharding_htable_insert(SFHtableShardingContext
            *sharding_ctx, const SFTwoIdsHashKey *key, void *arg);

    void *sf_sharding_htable_find(SFHtableShardingContext
            *sharding_ctx, const SFTwoIdsHashKey *key, void *arg);

    int sf_sharding_htable_delete(SFHtableShardingContext
            *sharding_ctx, const SFTwoIdsHashKey *key, void *arg);

#ifdef __cplusplus
}
#endif

#endif
