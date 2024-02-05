#include "main.h"

int main()
{
    const size_t cnt = 500000;
    char *tmp, *keys[cnt], *values[cnt];
    const int key_len = 11, value_len = 3;

    for (uint64_t i = 0; i < cnt; i++)
    {
        keys[i] = rand_string(key_len);
        values[i] = rand_string(value_len);
    }

    double time_spent;
    const size_t cap = 0;
    size_t i;
    clock_t begin, end;
    hm_map_t *map = hm_new(cap, &hash_djb2, &str_equals);
    printf("Swissmap Benchmarks (Key: String):\n");

    begin = clock();
    for (i = 0; i < cnt; i++)
        hm_insert(&map, keys[i], values[i]);
    end = clock();
    time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
    bench_print("set", cnt, time_spent);

    size_t idx;
    begin = clock();
    for (i = 0; i < cnt; i++)
        if (!hm_find(map, keys[i], &idx))
            printf("-----\n");
    end = clock();
    time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
    bench_print("get", cnt, time_spent);

    hm_key_t *match_key;
    size_t n_removed = 0;
    begin = clock();
    for (i = 0; i < cnt; i++)
    {
        hm_value_t *match_value = hm_remove(map, keys[i], &match_key);
        if (match_value)
        {
            free(match_key);
            free(match_value);
            n_removed++;
        }
    }
    end = clock();
    time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
    bench_print("del", cnt, time_spent);

    printf("\n\nAfter removing %llu values:\n", n_removed);
    hm_key_t *key_it;
    hm_value_t *value_it;
    size_t idx_it = 0, manual_cnt = 0;
    while (hm_iterate(map, &idx_it, &key_it, &value_it))
    {
        if (key_it)
        {
            printf("key = %s removed at idx %llu\n", key_it, idx_it - 1);
            free(key_it);
            free(value_it);
            manual_cnt++;
        }
    }
    printf("manual count of items = %llu\n", manual_cnt);
    printf("items = %llu\n", map->items);
    printf("size = %llu\n", map->size);
    printf("sentinel = %llu\n", map->sentinel);

    hm_clear(map);
    hm_erase(map);
    free(map);
}

char *rand_string(int length)
{
    static int seed = 25011984;
    char *string = STR_CHARS;
    size_t string_len = strlen(string);
    char *rand_string = NULL;

    srand(time(NULL) * length + ++seed);
    rand_string = malloc(sizeof(char) * (length + 1));
    for (int n = 0; n < length; n++)
    {
        short key = rand() % string_len;
        rand_string[n] = string[key];
    }
    rand_string[length] = '\0';
    return rand_string;
}

void bench_print(char *iter, size_t cnt, double time_spent)
{
    const size_t ns = 1000000000;
    printf("%s\t%d iters -> %lf seconds, %.0lf ns/iter %.0lf iter/sec\n",
           iter, cnt, time_spent, time_spent * ns / cnt, cnt / time_spent);
}
