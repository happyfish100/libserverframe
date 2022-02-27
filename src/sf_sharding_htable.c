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

#include <stdlib.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/fc_atomic.h"
#include "sf_sharding_htable.h"

static int init_allocators(SFHtableShardingContext *sharding_ctx,
        const int allocator_count, const int element_size,
        const int64_t element_limit)
{
    int result;
    int bytes;
    int alloc_elts_once;
    int64_t max_elts_per_allocator;
    struct fast_mblock_man *pa;
    struct fast_mblock_man *end;

    bytes = sizeof(struct fast_mblock_man) * allocator_count;
    sharding_ctx->allocators.elts = (struct fast_mblock_man *)fc_malloc(bytes);
    if (sharding_ctx->allocators.elts == NULL) {
        return ENOMEM;
    }

    max_elts_per_allocator = element_limit +
        (allocator_count - 1) / allocator_count;
    if (max_elts_per_allocator < 8 * 1024) {
        alloc_elts_once = max_elts_per_allocator;
    } else {
        alloc_elts_once = 8 * 1024;
    }

    end = sharding_ctx->allocators.elts + allocator_count;
    for (pa=sharding_ctx->allocators.elts; pa<end; pa++) {
        if ((result=fast_mblock_init_ex1(pa, "sharding-hkey", element_size,
                        alloc_elts_once, 0, NULL, NULL, true)) != 0)
        {
            return result;
        }
    }
    sharding_ctx->allocators.count = allocator_count;
    return 0;
}

static int init_sharding(SFHtableSharding *sharding,
        const int64_t per_capacity)
{
    int result;
    int bytes;
    struct fc_list_head *ph;
    struct fc_list_head *end;

    if ((result=init_pthread_lock(&sharding->lock)) != 0) {
        return result;
    }

    bytes = sizeof(struct fc_list_head) * per_capacity;
    sharding->hashtable.buckets = (struct fc_list_head *)fc_malloc(bytes);
    if (sharding->hashtable.buckets == NULL) {
        return ENOMEM;
    }
    end = sharding->hashtable.buckets + per_capacity;
    for (ph=sharding->hashtable.buckets; ph<end; ph++) {
        FC_INIT_LIST_HEAD(ph);
    }

    sharding->hashtable.capacity = per_capacity;
    sharding->element_count = 0;
    sharding->last_reclaim_time_ms = 1000LL * (int64_t)get_current_time();
    FC_INIT_LIST_HEAD(&sharding->lru);
    return 0;
}

static int init_sharding_array(SFHtableShardingContext *sharding_ctx,
        const int sharding_count, const int64_t per_elt_limit,
        const int64_t per_capacity)
{
    int result;
    int bytes;
    SFHtableSharding *ps;
    SFHtableSharding *end;

    bytes = sizeof(SFHtableSharding) * sharding_count;
    sharding_ctx->sharding_array.entries = (SFHtableSharding *)fc_malloc(bytes);
    if (sharding_ctx->sharding_array.entries == NULL) {
        return ENOMEM;
    }

    end = sharding_ctx->sharding_array.entries + sharding_count;
    for (ps=sharding_ctx->sharding_array.entries; ps<end; ps++) {
        ps->allocator = sharding_ctx->allocators.elts +
            (ps - sharding_ctx->sharding_array.entries) %
            sharding_ctx->allocators.count;
        ps->element_limit = per_elt_limit;
        ps->ctx = sharding_ctx;
        if ((result=init_sharding(ps, per_capacity)) != 0) {
            return result;
        }
    }

    sharding_ctx->sharding_array.count = sharding_count;
    return 0;
}

int sf_sharding_htable_init_ex(SFHtableShardingContext *sharding_ctx,
        const SFShardingHtableKeyType key_type,
        sf_sharding_htable_insert_callback insert_callback,
        sf_sharding_htable_find_callback find_callback,
        sf_sharding_htable_delete_callback delete_callback,
        sf_sharding_htable_accept_reclaim_callback reclaim_callback,
        const int sharding_count, const int64_t htable_capacity,
        const int allocator_count, const int element_size,
        int64_t element_limit, const int64_t min_ttl_ms,
        const int64_t max_ttl_ms, const double low_water_mark_ratio)
{
    int result;
    int64_t per_elt_limit;
    int64_t per_capacity;

    if (element_limit <= 0) {
        element_limit = 1000 * 1000;
    }

    if ((result=init_allocators(sharding_ctx, allocator_count,
                    element_size, element_limit)) != 0)
    {
        return result;
    }

    per_elt_limit = (element_limit + sharding_count - 1) / sharding_count;
    per_capacity = fc_ceil_prime(htable_capacity / sharding_count);
    if ((result=init_sharding_array(sharding_ctx, sharding_count,
                    per_elt_limit, per_capacity)) != 0)
    {
        return result;
    }

    sharding_ctx->key_type = key_type;
    sharding_ctx->insert_callback = insert_callback;
    sharding_ctx->find_callback = find_callback;
    sharding_ctx->delete_callback = delete_callback;
    sharding_ctx->accept_reclaim_callback = reclaim_callback;

    sharding_ctx->sharding_reclaim.enabled = (delete_callback == NULL);
    sharding_ctx->sharding_reclaim.elt_water_mark =
        per_elt_limit * low_water_mark_ratio;
    sharding_ctx->sharding_reclaim.min_ttl_ms = min_ttl_ms;
    sharding_ctx->sharding_reclaim.max_ttl_ms = max_ttl_ms;
    sharding_ctx->sharding_reclaim.elt_ttl_ms = (double)(sharding_ctx->
            sharding_reclaim.max_ttl_ms - sharding_ctx->
            sharding_reclaim.min_ttl_ms) / per_elt_limit;

    /*
    logInfo("per_elt_limit: %"PRId64", elt_water_mark: %d, "
            "elt_ttl_ms: %.2f", per_elt_limit, (int)sharding_ctx->
            sharding_reclaim.elt_water_mark, sharding_ctx->
            sharding_reclaim.elt_ttl_ms);
            */
    return 0;
}

static inline int compare_key(SFHtableShardingContext *sharding_ctx,
        const SFTwoIdsHashKey *key1, const SFTwoIdsHashKey *key2)
{
    int sub;

    if (sharding_ctx->key_type == sf_sharding_htable_key_ids_one) {
        return fc_compare_int64(key1->id1, key2->id1);
    } else {
        if ((sub=fc_compare_int64(key1->id1, key2->id1)) != 0) {
            return sub;
        }

        return fc_compare_int64(key1->id2, key2->id2);
    }
}

static inline SFShardingHashEntry *htable_find(
        SFHtableShardingContext *sharding_ctx,
        const SFTwoIdsHashKey *key, struct fc_list_head *bucket)
{
    int r;
    SFShardingHashEntry *current;

    fc_list_for_each_entry(current, bucket, dlinks.htable) {
        r = compare_key(sharding_ctx, key, &current->key);
        if (r < 0) {
            return NULL;
        } else if (r == 0) {
            return current;
        }
    }

    return NULL;
}

static inline void htable_insert(SFHtableShardingContext *sharding_ctx,
        SFShardingHashEntry *entry, struct fc_list_head *bucket)
{
    struct fc_list_head *previous;
    struct fc_list_head *current;
    SFShardingHashEntry *pe;

    previous = bucket;
    fc_list_for_each(current, bucket) {
        pe = fc_list_entry(current, SFShardingHashEntry, dlinks.htable);
        if (compare_key(sharding_ctx, &entry->key, &pe->key) < 0) {
            break;
        }

        previous = current;
    }

    fc_list_add_internal(&entry->dlinks.htable, previous, previous->next);
}

static SFShardingHashEntry *hash_entry_reclaim(SFHtableSharding *sharding)
{
    int64_t current_time_ms;
    int64_t reclaim_ttl_ms;
    int64_t delta;
    int64_t reclaim_count;
    int64_t reclaim_limit;
    SFShardingHashEntry *first;
    SFShardingHashEntry *entry;
    SFShardingHashEntry *tmp;

    if (sharding->element_count <= sharding->element_limit) {
        delta = sharding->element_count;
        if (sharding->ctx->sharding_reclaim.elt_water_mark > 0) {
            reclaim_count = sharding->element_count - sharding->ctx->
                sharding_reclaim.elt_water_mark;
            reclaim_limit = FC_MIN(reclaim_count, sharding->ctx->
                    sharding_reclaim.elt_water_mark);
        } else {
            reclaim_limit = sharding->element_count;
        }
    } else {
        delta = sharding->element_limit;
        reclaim_limit = (sharding->element_count - sharding->element_limit) +
            sharding->ctx->sharding_reclaim.elt_water_mark;
    }

    first = NULL;
    reclaim_count = 0;
    current_time_ms = 1000LL * (int64_t)get_current_time();
    reclaim_ttl_ms = (int64_t)(sharding->ctx->sharding_reclaim.max_ttl_ms -
            sharding->ctx->sharding_reclaim.elt_ttl_ms * delta);
    fc_list_for_each_entry_safe(entry, tmp, &sharding->lru, dlinks.lru) {
        if (current_time_ms - entry->last_update_time_ms <= reclaim_ttl_ms) {
            break;
        }

        if (sharding->ctx->accept_reclaim_callback != NULL &&
                !sharding->ctx->accept_reclaim_callback(entry))
        {
            continue;
        }

        fc_list_del_init(&entry->dlinks.htable);
        fc_list_del_init(&entry->dlinks.lru);
        if (first == NULL) {
            first = entry;  //keep the first
        } else {
            fast_mblock_free_object(sharding->allocator, entry);
            sharding->element_count--;
        }

        if (++reclaim_count > reclaim_limit) {
            break;
        }
    }

    if (reclaim_count > 0) {
        logInfo("sharding index: %d, element_count: %"PRId64", "
                "reclaim_ttl_ms: %"PRId64" ms, reclaim_count: %"PRId64", "
                "reclaim_limit: %"PRId64, (int)(sharding - sharding->ctx->
                    sharding_array.entries), sharding->element_count,
                reclaim_ttl_ms, reclaim_count, reclaim_limit);
    }

    return first;
}

static inline SFShardingHashEntry *htable_entry_alloc(
        SFHtableShardingContext *sharding_ctx,
        SFHtableSharding *sharding)
{
    SFShardingHashEntry *entry;
    int64_t current_time_ms;
    int64_t last_reclaim_time_ms;

    if (sharding_ctx->sharding_reclaim.enabled &&
            (sharding->element_count > sharding->ctx->
             sharding_reclaim.elt_water_mark))
    {
        current_time_ms = 1000LL * (int64_t)get_current_time();
        last_reclaim_time_ms = FC_ATOMIC_GET(sharding->last_reclaim_time_ms);
        if (current_time_ms - last_reclaim_time_ms > 100 &&
                __sync_bool_compare_and_swap(&sharding->last_reclaim_time_ms,
                    last_reclaim_time_ms, current_time_ms))
        {
            if ((entry=hash_entry_reclaim(sharding)) != NULL) {
                return entry;
            }
        }
    }

    entry = (SFShardingHashEntry *)fast_mblock_alloc_object(
            sharding->allocator);
    if (entry != NULL) {
        sharding->element_count++;
        entry->sharding = sharding;
    }

    return entry;
}

#define SET_SHARDING_AND_BUCKET(sharding_ctx, key) \
    SFHtableSharding *sharding; \
    struct fc_list_head *bucket;   \
    uint64_t hash_code;    \
    \
    hash_code = sf_sharding_htable_key_ids_one == sharding_ctx-> \
                key_type ? key->id1 : key->id1 + key->id2; \
    sharding = sharding_ctx->sharding_array.entries +   \
        hash_code % sharding_ctx->sharding_array.count; \
    bucket = sharding->hashtable.buckets +   \
        key->id1 % sharding->hashtable.capacity


void *sf_sharding_htable_find(SFHtableShardingContext
        *sharding_ctx, const SFTwoIdsHashKey *key, void *arg)
{
    void *data;
    SFShardingHashEntry *entry;
    SET_SHARDING_AND_BUCKET(sharding_ctx, key);

    PTHREAD_MUTEX_LOCK(&sharding->lock);
    entry = htable_find(sharding_ctx, key, bucket);
    if (entry != NULL && sharding_ctx->find_callback != NULL) {
        data = sharding_ctx->find_callback(entry, arg);
    } else {
        data = entry;
    }
    PTHREAD_MUTEX_UNLOCK(&sharding->lock);

    return data;
}

int sf_sharding_htable_delete(SFHtableShardingContext
        *sharding_ctx, const SFTwoIdsHashKey *key, void *arg)
{
    int result;
    SFShardingHashEntry *entry;

    if (sharding_ctx->delete_callback != NULL) {
        SET_SHARDING_AND_BUCKET(sharding_ctx, key);
        PTHREAD_MUTEX_LOCK(&sharding->lock);
        entry = htable_find(sharding_ctx, key, bucket);
        if (entry != NULL) {
            if (sharding_ctx->delete_callback(entry, arg)) {
                fc_list_del_init(&entry->dlinks.htable);
                if (sharding_ctx->sharding_reclaim.enabled) {
                    fc_list_del_init(&entry->dlinks.lru);
                }
                fast_mblock_free_object(sharding->allocator, entry);
                sharding->element_count--;
            }
            result = 0;
        } else {
            result = ENOENT;
        }
        PTHREAD_MUTEX_UNLOCK(&sharding->lock);
    } else {
        logError("file: "__FILE__", line: %d, "
                "delete callback is NULL!", __LINE__);
        result = EINVAL;
    }

    return result;
}

int sf_sharding_htable_insert(SFHtableShardingContext
        *sharding_ctx, const SFTwoIdsHashKey *key, void *arg)
{
    SFShardingHashEntry *entry;
    bool new_create;
    int result;
    SET_SHARDING_AND_BUCKET(sharding_ctx, key);

    PTHREAD_MUTEX_LOCK(&sharding->lock);
    do {
        if ((entry=htable_find(sharding_ctx, key, bucket)) == NULL) {
            if ((entry=htable_entry_alloc(sharding_ctx, sharding)) == NULL) {
                result = ENOMEM;
                break;
            }

            new_create = true;
            entry->key = *key;
            htable_insert(sharding_ctx, entry, bucket);
            if (sharding_ctx->sharding_reclaim.enabled) {
                fc_list_add_tail(&entry->dlinks.lru, &sharding->lru);
            }
        } else {
            new_create = false;
            if (sharding_ctx->sharding_reclaim.enabled) {
                fc_list_move_tail(&entry->dlinks.lru, &sharding->lru);
            }
        }

        entry->last_update_time_ms = 1000LL * (int64_t)get_current_time();
        result = sharding_ctx->insert_callback(
                entry, arg, new_create);
    } while (0);
    PTHREAD_MUTEX_UNLOCK(&sharding->lock);

    return result;
}
