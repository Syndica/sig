#ifndef HM_H
#define HM_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __aarch64__
#include <arm_neon.h>
#else
#include <immintrin.h>
#endif

#ifndef HM_DEFAULT_N_GROUPS
#define HM_DEFAULT_N_GROUPS (1)
#endif

#ifndef HM_LOAD_FACTOR
#define HM_LOAD_FACTOR (0.75)
#endif

#ifndef HM_RESIZE_FACTOR
#define HM_RESIZE_FACTOR (2)
#endif

#define HM_GROUP_SIZE (16)
#define HM_CONTROL_SIZE (16)

typedef char hm_key_t;
typedef char hm_value_t;

#ifdef __aarch64__
typedef int32x4_t hm_control_t;
#elif __x86_64__
typedef __m128i hm_control_t;
#endif

typedef int8_t hm_metadata_t;

typedef size_t (*hm_hashfn_t)(hm_key_t *key);
typedef bool (*hm_cmpfn_t)(hm_key_t *key1, hm_key_t *key2);

typedef enum
{
    HM_EMPTY = 0b10000000,
    HM_DELETED = 0b11111111
} hm_ctrl_e;

typedef struct
{
    size_t pos;
    hm_metadata_t meta;
} hm_hash_t;

typedef struct
{
    hm_control_t _ctrl;
    hm_key_t *key[HM_CONTROL_SIZE];
    hm_hash_t hash[HM_CONTROL_SIZE];
} hm_group_t;

typedef struct
{
    hm_group_t *groups;
    hm_value_t **values;
    size_t items;
    size_t n_groups;
    size_t sentinel;
    size_t size;

    hm_hashfn_t hashfn;
    hm_cmpfn_t cmpfn;
} hm_map_t;

size_t hash_djb2(char *str);
bool str_equals(char *val1, char *val2);
static inline hm_control_t zero_lowest_n_bytes(
    hm_control_t _ctrl, hm_metadata_t n)
    __attribute__((always_inline));
static inline size_t hm_pos(
    size_t hash)
    __attribute__((always_inline));
static inline hm_metadata_t hm_meta(
    size_t hash)
    __attribute__((always_inline));
// TODO change hm_group_pos return type to hm_metadata_t
static inline hm_metadata_t hm_group_pos(
    size_t idx)
    __attribute__((always_inline));
static inline size_t hm_idx(
    size_t group, hm_metadata_t group_pos)
    __attribute__((always_inline));
static inline hm_hash_t hm_hash(
    hm_map_t *map, hm_key_t *key)
    __attribute__((always_inline));
static inline bool hm_should_resize(
    hm_map_t *map)
    __attribute__((always_inline));
static inline uint16_t hm_match_full(
    hm_map_t *map, size_t group)
    __attribute__((always_inline));
static inline size_t hm_group(
    size_t idx)
    __attribute__((always_inline));
static inline size_t hm_sentinel_group(
    hm_map_t *map)
    __attribute__((always_inline));
static inline size_t hm_last_group(
    hm_map_t *map)
    __attribute__((always_inline));

static uint16_t inline hm_probe(
    hm_metadata_t meta, hm_control_t _ctrl)
    __attribute__((always_inline));
static inline uint16_t hm_probe_from(
    hm_metadata_t group_pos, hm_metadata_t meta,
    hm_control_t _ctrl)
    __attribute__((always_inline));
static inline bool hm_match_metadata(
    hm_map_t *map, hm_metadata_t meta, size_t group,
    size_t *match_idx)
    __attribute__((always_inline));
static inline bool hm_match_metadata_from(
    hm_map_t *map, hm_metadata_t meta, hm_hash_t *hash,
    size_t group, hm_metadata_t group_pos, size_t *match_idx)
    __attribute__((always_inline));
static inline hm_value_t *hm_find_hash(
    hm_map_t *map, hm_hash_t *hash, hm_key_t *key,
    size_t group, hm_metadata_t group_pos, size_t *match_idx)
    __attribute__((always_inline));

static inline hm_map_t *hm_resize(
    hm_map_t *map)
    __attribute__((always_inline));
static inline void hm_insert_at(
    hm_map_t *map, size_t group, hm_metadata_t group_pos,
    hm_hash_t hash, hm_key_t *key, hm_value_t *value)
    __attribute__((always_inline));

hm_value_t *hm_find(hm_map_t *map, hm_key_t *key, size_t *match_idx);
hm_map_t *hm_new(size_t n_groups, hm_hashfn_t hashfn, hm_cmpfn_t cmpfn);
hm_map_t *hm_new_managed(size_t n_groups);
void hm_clear(hm_map_t *map);
void hm_erase(hm_map_t *map);
void hm_insert(hm_map_t **map, hm_key_t *key, hm_value_t *value);
hm_value_t *hm_remove(hm_map_t *map, hm_key_t *key, hm_key_t **match_key);
bool hm_iterate(hm_map_t *map, size_t *idx, hm_key_t **key_ref, hm_value_t **value_ref);

#endif
