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

void *art_insert(struct art *art, const unsigned char *key, size_t key_len,
                 void *value);

void *art_get(struct art *art, const unsigned char *key, size_t key_len);

void *art_delete(struct art *art, const unsigned char *key, size_t key_len);

typedef int(*art_iter_callback)(void *data, const unsigned char *key, uint32_t key_len, void *value);

int art_iter(struct art *art, art_iter_callback cb, void *data);

typedef int (*art_iter_value_callback)(void *data, void *value);

int art_iter_value(struct art *art, art_iter_value_callback cb, void *data);

int art_iter_value_prefix(struct art *art, const unsigned char *key,
                          size_t key_len, art_iter_value_callback cb,
                          void *data);

#ifdef __cplusplus
}
#endif