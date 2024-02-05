#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <time.h>
#include "hashmap.h"

#define STR_CHARS \
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!"

char *rand_string(int length);
bool str_equals(char *val1, char *val2);
void bench_print(char *op, size_t cnt, double time_spent);

#endif
