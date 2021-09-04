// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MAX_PREFIX_KEY_LEN
#define MAX_PREFIX_KEY_LEN 8
#endif

typedef uint64_t node_slot_t;

struct art {
    node_slot_t root;
    size_t size;
};

void art_init(struct art *art);

void art_free(struct art *art);

void *art_insert(struct art *art, const char *key, size_t key_len, void *value);

void *art_get(struct art *art, const char *key, size_t key_len);

void *art_delete(struct art *art, const char *key, size_t key_len);

#ifdef __cplusplus
}
#endif