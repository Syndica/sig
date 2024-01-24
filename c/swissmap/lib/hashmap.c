#include <stdlib.h>
#include <stdalign.h>

#include "hashmap.h"

alignas(32) static const hm_metadata_t mask[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

static hm_control_t zero_lowest_n_bytes(hm_control_t _ctrl, hm_metadata_t n)
{
#ifdef __aarch64__
    // NEON implementation
    int32x4_t _m = vld1q_s32((const int32_t *)&mask[16 - n]);
    return vandq_s32(_ctrl, _m);
#else
    // SSE implementation
    hm_control_t _m = _mm_loadu_si128((hm_control_t *)&mask[16 - n]);
    return _mm_and_si128(_ctrl, _m);
#endif
}

static size_t hm_pos(size_t hash)
{
    return hash >> 7;
}

static hm_metadata_t hm_meta(size_t hash)
{
    return hash & 0x7f;
}

static size_t hm_idx(size_t group, hm_metadata_t group_pos)
{
    return (group * HM_GROUP_SIZE) + group_pos;
}

static size_t hm_group(size_t idx)
{
    return idx / HM_GROUP_SIZE;
}

static hm_metadata_t hm_group_pos(size_t idx)
{
    return idx % HM_GROUP_SIZE;
}

static size_t hm_sentinel_group(hm_map_t *map)
{
    return hm_group(map->sentinel) + 1;
}

static size_t hm_last_group(hm_map_t *map)
{
    return hm_group(map->size - 1) + 1;
}

static hm_hash_t hm_hash(hm_map_t *map, hm_key_t *key)
{
    hm_hash_t hash;
    size_t h = map->hashfn(key);
    hash.pos = hm_pos(h);
    hash.meta = hm_meta(h);
    return hash;
}

static bool hm_should_resize(hm_map_t *map)
{
    return map->items >= (HM_LOAD_FACTOR * map->size);
}

uint16_t neon_movemask_epi8(uint8x16_t input)
{
    // Compare each byte with zero
    uint8x16_t mask = vreinterpretq_u8_s8(vshrq_n_s8(vreinterpretq_s8_u8(input), 7));

    // Create a lookup table
    const uint8x8_t bit_mask = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
    uint8x8_t low = vand_u8(vget_low_u8(mask), bit_mask);
    uint8x8_t high = vand_u8(vget_high_u8(mask), bit_mask);

    // Sum up the bits
    uint16_t low_sum = vaddv_u8(low);   // Sum up the lower 8 bytes
    uint16_t high_sum = vaddv_u8(high); // Sum up the higher 8 bytes

    return low_sum | (high_sum << 8);
}

static uint16_t hm_match_full(hm_map_t *map, size_t group)
{
#ifdef __aarch64__
    return neon_movemask_epi8(map->groups[group]._ctrl);
#else
    return ~(_mm_movemask_epi8(map->groups[group]._ctrl));
#endif
}

static uint16_t hm_probe(hm_metadata_t meta, hm_control_t _ctrl)
{
    hm_control_t _match;
#ifdef __aarch64__
    _match = vdupq_n_s8(meta);
    return neon_movemask_epi8(vceqq_s8(_match, _ctrl));
#else
    _match = _mm_set1_epi8(meta);
    return _mm_movemask_epi8(_mm_cmpeq_epi8(_match, _ctrl));
#endif
}

static uint16_t hm_probe_from(hm_metadata_t group_pos, hm_metadata_t meta,
                              hm_control_t _ctrl)
{
    hm_control_t _match;
#ifdef __aarch64__
    _match = vdupq_n_s8(meta);
    return neon_movemask_epi8(
        zero_lowest_n_bytes(
            vceqq_s8(_match, _ctrl), group_pos));
#else
    _match = _mm_set1_epi8(meta);
    return _mm_movemask_epi8(
        zero_lowest_n_bytes(
            _mm_cmpeq_epi8(_match, _ctrl), group_pos));
#endif
}

unsigned int trailing_zeroes(unsigned int value)
{
    if (value == 0)
    {
        return 32;
    }
#ifdef __aarch64__
    return __builtin_ctz(value);
#else
    return _tzcnt_u32(value);
#endif
}

static bool hm_match_metadata(hm_map_t *map, hm_metadata_t meta,
                              size_t group, size_t *match_idx)
{
    hm_metadata_t match_group_pos = trailing_zeroes(hm_probe(
        meta, map->groups[group]._ctrl));

    *match_idx = hm_idx(group, match_group_pos);
    return (match_group_pos < 32) ? true : false;
}

static bool hm_match_metadata_from(hm_map_t *map, hm_metadata_t meta,
                                   hm_hash_t *hash, size_t group,
                                   hm_metadata_t group_pos, size_t *match_idx)
{
    hm_metadata_t match_group_pos = trailing_zeroes(hm_probe_from(
        group_pos, meta, map->groups[group]._ctrl));

    *match_idx = hm_idx(group, match_group_pos);
    return (match_group_pos < 32) ? true : false;
}

unsigned int blsr_u32(unsigned int x)
{
    return x & (x - 1);
}

static hm_value_t *hm_find_hash(hm_map_t *map,
                                hm_hash_t *hash, hm_key_t *key,
                                size_t group, hm_metadata_t group_pos, size_t *match_idx)
{
    uint16_t matches = hm_probe_from(
        group_pos, hash->meta, map->groups[group]._ctrl);

    while (matches)
    {
        hm_metadata_t match_group_pos = trailing_zeroes(matches);

        if (map->cmpfn(map->groups[group].key[match_group_pos], key))
        {
            *match_idx = hm_idx(group, match_group_pos);
            return map->values[*match_idx];
        }

        matches = blsr_u32(matches);
    }
    if (hm_match_metadata_from(
            map, HM_EMPTY, hash, group, group_pos, match_idx))
        return NULL;

    size_t end_group = hm_sentinel_group(map);

    while (true)
    {
        group = (group + 1) % end_group;

        matches = hm_probe(hash->meta, map->groups[group]._ctrl);

        while (matches)
        {
            hm_metadata_t match_group_pos = trailing_zeroes(matches);

            if (map->cmpfn(map->groups[group].key[match_group_pos], key))
            {
                *match_idx = hm_idx(group, match_group_pos);
                return map->values[*match_idx];
            }

            matches = blsr_u32(matches);
        }
        if (hm_match_metadata(map, HM_EMPTY, group, match_idx))
            return NULL;
    }
}

hm_value_t *hm_find(hm_map_t *map, hm_key_t *key, size_t *match_idx)
{
    hm_hash_t hash = hm_hash(map, key);
    size_t idx = hash.pos % map->size;
    size_t group = hm_group(idx);
    hm_metadata_t group_pos = hm_group_pos(idx);
    return hm_find_hash(map, &hash, key, group, group_pos, match_idx);
}

hm_map_t *hm_new_managed(size_t n_groups)
{
    return hm_new(n_groups, &hash_djb2, &str_equals);
}

hm_map_t *hm_new(size_t n_groups, hm_hashfn_t hashfn, hm_cmpfn_t cmpfn)
{
    hm_map_t *map = malloc(sizeof(hm_map_t));
    if (!map)
        return NULL;

    map->n_groups = n_groups;
    map->sentinel = 0;
    map->size = map->n_groups * HM_GROUP_SIZE;
    map->items = 0;
    map->hashfn = hashfn;
    map->cmpfn = cmpfn;

    if (map->size > 0)
    {
        map->values = malloc(map->size * sizeof(hm_value_t *));
        map->groups = malloc(map->n_groups * sizeof(hm_group_t));
        if (!map->values || !map->groups)
            return NULL;

        hm_control_t _empty;
#ifdef __aarch64__
        _empty = vdupq_n_s8(HM_EMPTY);
#else
        _empty = _mm_set1_epi8(HM_EMPTY);
#endif
        for (size_t group = 0; group < map->n_groups; group++)
        {
            map->groups[group]._ctrl = _empty;
        }
    }
    else
    {
        map->values = NULL;
        map->groups = NULL;
    }
    return map;
}

void hm_clear(hm_map_t *map)
{
    hm_control_t _empty;
#ifdef __aarch64__
    _empty = vdupq_n_s8(HM_EMPTY);
#else
    _empty = _mm_set1_epi8(HM_EMPTY);
#endif
    size_t end_group = hm_sentinel_group(map);

    for (size_t group = 0; group < end_group; group++)
        map->groups[group]._ctrl = _empty;
    map->items = 0;
}

void hm_erase(hm_map_t *map)
{
    free(map->groups);
    free(map->values);
}

hm_map_t *hm_resize(hm_map_t *map)
{
    size_t new_n_groups = (map->n_groups == 0)
                              ? HM_DEFAULT_N_GROUPS
                              : HM_RESIZE_FACTOR * map->n_groups;
    hm_map_t *new_map = hm_new(new_n_groups, map->hashfn, map->cmpfn);

    if (map->n_groups > 0)
    {
        hm_metadata_t old_group_pos;
        size_t old_idx, old_group;
        size_t old_end_group = hm_sentinel_group(map);

        size_t new_idx, new_group;
        hm_metadata_t new_group_pos;

        hm_hash_t hash;
        uint16_t match_full;

        for (old_group = 0; old_group < old_end_group; old_group++)
        {
            match_full = hm_match_full(map, old_group);

            while (match_full)
            {
                old_group_pos = trailing_zeroes(match_full);

                old_idx = hm_idx(old_group, old_group_pos);
                hash = map->groups[old_group].hash[old_group_pos];

                new_idx = hash.pos % new_map->size;
                new_group = hm_group(new_idx);
                new_group_pos = hm_group_pos(new_idx);

                hm_insert_at(
                    new_map, new_group, new_group_pos, hash,
                    map->groups[old_group].key[old_group_pos],
                    map->values[old_idx]);

                match_full = blsr_u32(match_full);
            }
        }
    }

    hm_erase(map);
    free(map);
    return new_map;
}

static void hm_insert_at(hm_map_t *map, size_t group, hm_metadata_t group_pos,
                         hm_hash_t hash, hm_key_t *key, hm_value_t *value)
{
    size_t match_idx, match_idx_emp, match_idx_del;

    if (hm_match_metadata_from(
            map, HM_EMPTY, &hash, group, group_pos, &match_idx_emp) |
        hm_match_metadata_from(
            map, HM_DELETED, &hash, group, group_pos, &match_idx_del))
    {
        match_idx = (match_idx_emp < match_idx_del)
                        ? match_idx_emp
                        : match_idx_del;
        group_pos = hm_group_pos(match_idx);

        ((hm_metadata_t *)&(map->groups[group]._ctrl))[group_pos] = hash.meta;
        map->groups[group].key[group_pos] = key;
        map->groups[group].hash[group_pos] = hash;
        map->values[match_idx] = value;
        map->items++;

        if (match_idx > map->sentinel)
            map->sentinel = match_idx;
        return;
    }

    size_t end_group = hm_last_group(map);

    while (true)
    {
        group = (group + 1) % end_group;

        if (hm_match_metadata(map, HM_EMPTY, group, &match_idx_emp) | hm_match_metadata(map, HM_DELETED, group, &match_idx_del))
        {
            match_idx = (match_idx_emp < match_idx_del)
                            ? match_idx_emp
                            : match_idx_del;
            group_pos = hm_group_pos(match_idx);

            ((hm_metadata_t *)&(map->groups[group]._ctrl))[group_pos] = hash.meta;
            map->groups[group].hash[group_pos] = hash;
            map->groups[group].key[group_pos] = key;
            map->values[match_idx] = value;
            map->items++;

            if (match_idx > map->sentinel)
                map->sentinel = match_idx;
            return;
        }
    }
}

void hm_insert(hm_map_t **map_ref, hm_key_t *key, hm_value_t *value)
{
    if (hm_should_resize(*map_ref) || (*map_ref)->size == 0)
        *map_ref = hm_resize((*map_ref));

    size_t match_idx;
    hm_hash_t hash = hm_hash((*map_ref), key);
    size_t idx = hash.pos % (*map_ref)->size;
    size_t group = hm_group(idx);
    hm_metadata_t group_pos = hm_group_pos(idx);

    hm_value_t *match_value = hm_find_hash(
        (*map_ref), &hash, key, group, group_pos, &match_idx);
    if (match_value)
    {
        free(key);
        free(match_value);
        return;
    }
    hm_insert_at((*map_ref), group, group_pos, hash, key, value);
}

hm_value_t *hm_remove(hm_map_t *map, hm_key_t *key, hm_key_t **match_key_ref)
{
    hm_hash_t hash = hm_hash(map, key);
    size_t idx = hash.pos % map->size;
    size_t group = hm_group(idx);
    hm_metadata_t group_pos = hm_group_pos(idx);
    size_t match_idx;

    hm_value_t *match_value = hm_find_hash(
        map, &hash, key, group, group_pos, &match_idx);
    if (match_value)
    {
        group = hm_group(match_idx);
        group_pos = hm_group_pos(match_idx);

        ((hm_metadata_t *)&(map->groups[group]._ctrl))[group_pos] = HM_DELETED;
        *match_key_ref = map->groups[group].key[group_pos];
        map->items--;

        if (match_idx == map->sentinel)
            map->sentinel--;
        return match_value;
    }
    return NULL;
}

bool hm_iterate(hm_map_t *map, size_t *idx,
                hm_key_t **key_ref, hm_value_t **value_ref)
{
    if (*idx > map->sentinel)
        return false;

    size_t group = hm_group(*idx);
    hm_metadata_t group_pos = hm_group_pos(*idx);

    if (((hm_metadata_t *)&(map->groups[group]._ctrl))[group_pos] < 0)
    {
        *key_ref = NULL;
        *value_ref = NULL;
    }
    else
    {
        *key_ref = map->groups[group].key[group_pos];
        *value_ref = map->values[*idx];
    }
    (*idx)++;
    return true;
}

/*
 * DJB2 Hash Function.
 */
size_t hash_djb2(char *str)
{
    size_t hash = 5381;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c;
    return hash;
}

bool str_equals(char *val1, char *val2)
{
    return !strcmp(val1, val2);
}
