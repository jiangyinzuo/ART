// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t node_slot_t;

struct art {
    node_slot_t root;
    size_t size;
};

void art_init(struct art *art);

void *art_insert(struct art *art, const char *key, size_t key_len, void *value);

void *art_get(struct art *art, const char *key, size_t key_len);

#ifdef __cplusplus
}
#endif