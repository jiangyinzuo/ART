// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#include <assert.h>
#include <emmintrin.h>
#include <immintrin.h>
#include <stdlib.h>
#include <string.h>

#include "art/art.h"

_Static_assert(8 <= MAX_PREFIX_KEY_LEN && MAX_PREFIX_KEY_LEN <= 255, "");

#define NUM_CHILDREN_MASK 0xff00000000000000
#define PTR_MASK 0x00fffffffffffff8
#define TYPE_MASK 0b111

#define LIKELY(x) (__builtin_expect((x), 1))
#define UNLIKELY(x) (__builtin_expect((x), 0))

_Static_assert(sizeof(struct art) == 16, "");

enum node_type {
    NODE_VALUE = 0,
    NODE_1 = 1,
    NODE_4 = 2,
    NODE_16 = 3,
    NODE_48 = 4,
    NODE_256 = 5,
};

typedef struct __attribute__((packed)) {
    node_slot_t child;
    uint8_t key_len;
    unsigned char prefix_key[];
} node1_t;

_Static_assert(sizeof(node1_t) == 8 + 1, "");

typedef struct __attribute__((packed)) {
    node_slot_t children[4];
    unsigned char keys[4];
    uint8_t key_len;
    unsigned char prefix_key[];
} node4_t;

_Static_assert(sizeof(node4_t) == 4 * 8 + 4 + 1, "");

typedef struct __attribute__((packed)) {
    node_slot_t children[16];
    unsigned char keys[16];
    uint8_t key_len;
    unsigned char prefix_key[];
} node16_t;

_Static_assert(sizeof(node16_t) == 16 * 8 + 16 + 1, "");

typedef struct __attribute__((packed)) {
    uint8_t keys[256];
    node_slot_t children[48];
    uint64_t bitmap;
    uint8_t key_len;
    unsigned char prefix_key[];
} node48_t;

_Static_assert(sizeof(node48_t) == 256 + 48 * 8 + 8 + 1, "");

typedef struct __attribute__((packed)) {
    node_slot_t children[256];
    uint8_t key_len;
    unsigned char prefix_key[];
} node256_t;

_Static_assert(sizeof(node256_t) == 256 * 8 + 1, "");

static inline node_slot_t ptr_to_slot(void *ptr, enum node_type ty) {
    assert(ty <= NODE_1);
    assert(((uint64_t)ptr & ~PTR_MASK) == 0);
    return (uint64_t)ptr | ty;
}

static inline node_slot_t ptr_to_slot_num_children(void *ptr, enum node_type ty,
                                                   uint8_t num_children) {
    assert(ty >= NODE_4);
    assert(((uint64_t)ptr & ~PTR_MASK) == 0);
    return (uint64_t)ptr | ty | (((uint64_t)num_children) << 56);
}

static inline void set_num_children(node_slot_t *node_slot,
                                    uint8_t num_children) {
    *node_slot =
        (*node_slot & ~NUM_CHILDREN_MASK) | (((uint64_t)num_children) << 56);
}

static inline enum node_type get_type(node_slot_t n) { return n & TYPE_MASK; }

static inline void *get_raw(node_slot_t n) { return (void *)(n & PTR_MASK); }

static inline void clear_raw(node_slot_t *n) { *n = *n & ~PTR_MASK; }

static inline uint8_t get_num_children(node_slot_t n) { return n >> 56; }

static unsigned char *get_prefix_key(node_slot_t n) {
    enum node_type ty = get_type(n);
    unsigned char *base = get_raw(n);
    static size_t table[] = {sizeof(node1_t), sizeof(node4_t), sizeof(node16_t),
                             sizeof(node48_t), sizeof(node256_t)};
    return base + table[ty - NODE_1];
}

static inline uint8_t get_prefix_key_len(const unsigned char *prefix_key) {
    return prefix_key[-1];
}

static inline void dec_prefix_key_len(unsigned char *prefix_key, uint8_t len) {
    assert((uint8_t)prefix_key[-1] >= len);
    *(uint8_t *)(prefix_key - 1) = (uint8_t)prefix_key[-1] - len;
}

static node1_t *new_node1(const unsigned char *prefix_key,
                          uint8_t prefix_key_len, node_slot_t child) {
    node1_t *node_ptr = malloc(sizeof(node1_t) + prefix_key_len);
    assert(((uint64_t)node_ptr & TYPE_MASK) == 0);
    node_ptr->child = child;
    node_ptr->key_len = prefix_key_len;
    memcpy(node_ptr->prefix_key, prefix_key, prefix_key_len);
    return node_ptr;
}

static void new_node1_or_assign_node_value(node_slot_t **cur_node_slot_ptr,
                                           const unsigned char *key,
                                           uint8_t key_len, node_slot_t child) {
    if (key_len) {
        node1_t *node_ptr = new_node1(key, key_len, child);

        **cur_node_slot_ptr = ptr_to_slot(node_ptr, NODE_1);
        *cur_node_slot_ptr = &node_ptr->child;
    } else {
        **cur_node_slot_ptr = child;
    }
}

static void new_node4(node_slot_t **cur_node_slot_ptr, const unsigned char *key,
                      uint8_t key_len, node_slot_t child) {
    node_slot_t old_value = **cur_node_slot_ptr;
    assert(get_type(old_value) == NODE_VALUE);
    node4_t *node_ptr =
        calloc(sizeof(node4_t) + key_len, sizeof(unsigned char));
    assert(((uint64_t)node_ptr & TYPE_MASK) == 0);

    // node_ptr->keys[0] = '\0';
    node_ptr->children[0] = old_value;
    assert(*key);
    node_ptr->keys[1] = key[key_len];
    node_ptr->children[1] = child;
    node_ptr->key_len = key_len;
    memcpy(node_ptr->prefix_key, key, key_len);
    **cur_node_slot_ptr = ptr_to_slot_num_children(node_ptr, NODE_4, 2);
    *cur_node_slot_ptr = &node_ptr->children[1];
}

static void split_prefix_key_to_node4(node_slot_t **cur_node_slot_ptr,
                                      const unsigned char *prefix_key,
                                      size_t common_prefix_key_len,
                                      unsigned char new_child) {
    node_slot_t old_node = **cur_node_slot_ptr;

    node4_t *new_node4 =
        calloc(sizeof(node4_t) + common_prefix_key_len, sizeof(unsigned char));
    assert(((uint64_t)new_node4 & TYPE_MASK) == 0);

    uint8_t prefix_key_len = get_prefix_key_len(prefix_key);
    new_node4->keys[0] = prefix_key_len == common_prefix_key_len
                             ? 0
                             : prefix_key[common_prefix_key_len];
    node1_t *old_node1;
    _Bool free_old_node1 = 0;
    if (UNLIKELY(prefix_key_len <= common_prefix_key_len + 1 &&
                 get_type(old_node))) {
        old_node1 = (node1_t *)get_raw(old_node);
        old_node = old_node1->child;
        free_old_node1 = 1;
    }

    new_node4->children[0] = old_node;
    new_node4->keys[1] = new_child;
    new_node4->key_len = common_prefix_key_len;

    // move the common prefix to new node
    memcpy(new_node4->prefix_key, prefix_key, common_prefix_key_len);
    memmove((void *)prefix_key, prefix_key + common_prefix_key_len + 1,
            prefix_key_len - common_prefix_key_len - 1);
    dec_prefix_key_len((unsigned char *)prefix_key, common_prefix_key_len + 1);

    **cur_node_slot_ptr = ptr_to_slot_num_children(new_node4, NODE_4, 2);
    *cur_node_slot_ptr = &new_node4->children[1];
    if (free_old_node1)
        free(old_node1);
}

static size_t mem_cmp_mismatch(const unsigned char *buf1,
                               const unsigned char *buf2, size_t n) {
    int i = 0;
    while (*buf1++ == *buf2++) {
        if (++i == n) {
            return n;
        }
    }
    return i;
}

static inline uint8_t key_compare(const unsigned char **key, size_t *key_len,
                                  const unsigned char *prefix_key,
                                  uint8_t prefix_key_len) {
    assert(prefix_key_len);
    size_t mismatch_idx = mem_cmp_mismatch(*key, prefix_key, prefix_key_len);
    *key += mismatch_idx;
    *key_len -= mismatch_idx;
    return mismatch_idx;
}

static inline node_slot_t node4_find_child(node4_t *node4, unsigned char key,
                                           uint8_t num_children) {
    for (uint8_t i = 0; i < num_children; ++i) {
        if (node4->keys[i] == key) {
            return node4->children[i];
        }
    }
    return 0;
}

static int node16_find_child_idx(node16_t *node16, unsigned char key,
                                 uint8_t num_children) {
    __m128i key_spans = _mm_set1_epi8((char)key);
    __m128i _partial_key = _mm_load_si128((const __m128i *)(&node16->keys));
    __m128i result = _mm_cmpeq_epi8(key_spans, _partial_key);
    int mask = (1 << num_children) - 1;
    int idx = _mm_movemask_epi8(result);
    idx &= mask;
    return idx;
}

static inline node_slot_t node16_find_child(node16_t *node16, unsigned char key,
                                            uint8_t num_children) {
    int idx = node16_find_child_idx(node16, key, num_children);
    return idx > 0 ? node16->children[_tzcnt_u32((uint32_t)idx)] : 0;
}

static inline node_slot_t node48_find_child(node48_t *node48, unsigned char key,
                                            uint8_t _num_children) {
    uint8_t child_idx = node48->keys[key];
    return child_idx ? node48->children[child_idx - 1] : 0;
}

static inline node_slot_t node256_find_child(node256_t *node256,
                                             unsigned char key,
                                             uint8_t _num_children) {
    return node256->children[key];
}

static node_slot_t *node4_expand_to_node16(node_slot_t *cur_node_ptr,
                                           node4_t *node4, unsigned char key) {
    node16_t *node16 =
        calloc(sizeof(node16_t) + node4->key_len, sizeof(unsigned char));
    node16->key_len = node4->key_len;
    memcpy(node16->keys, node4->keys, sizeof(unsigned char) * 4);
    memcpy(node16->children, node4->children, sizeof(node_slot_t) * 4);
    memcpy(node16->prefix_key, node4->prefix_key, node16->key_len);
    node16->keys[4] = key;
    *cur_node_ptr = ptr_to_slot_num_children(node16, NODE_16, 5);
    free(node4);
    return node16->children + 4;
}

static node_slot_t *node16_expand_to_node48(node_slot_t *cur_node_ptr,
                                            node16_t *node16,
                                            unsigned char key) {
    node48_t *node48 =
        calloc(sizeof(node48_t) + node16->key_len, sizeof(unsigned char));
    node48->bitmap = UINT64_MAX ^ 0x1ffff;
    assert(((uint64_t)&node48->keys & 0b1111) == 0);

    node48->key_len = node16->key_len;
    for (uint8_t i = 0; i < 16; ++i) {
        // keys['x'] == 0 means 'x' doesn't have child.
        assert(key != node16->keys[i]);
        node48->keys[node16->keys[i]] = i + 1;
        node48->children[i] = node16->children[i];
    }
    memcpy(node48->prefix_key, node16->prefix_key, node48->key_len);
    node48->keys[key] = 17;
    *cur_node_ptr = ptr_to_slot_num_children(node48, NODE_48, 17);
    free(node16);
    return node48->children + 16;
}

static node_slot_t *node48_expand_to_node256(node_slot_t *cur_node_ptr,
                                             node48_t *node48,
                                             unsigned char key) {
    node256_t *node256 =
        calloc(sizeof(node256_t) + node48->key_len, sizeof(unsigned char));

    node256->key_len = node48->key_len;
    for (unsigned int i = 0; i <= 255; ++i) {
        uint8_t child_idx;
        if ((child_idx = LIKELY(node48->keys[i])) > 0) {
            assert(1 <= child_idx && child_idx <= 48);
            node256->children[i] = node48->children[child_idx - 1];
        }
    }
    memcpy(node256->prefix_key, node48->prefix_key, node256->key_len);
    *cur_node_ptr = ptr_to_slot_num_children(node256, NODE_256, 49);
    free(node48);
    return node256->children + (uint8_t)key;
}

static node_slot_t *node4_find_or_append_child(node_slot_t *cur_node_ptr,
                                               node4_t *node4,
                                               unsigned char key,
                                               uint8_t num_children) {
    // find child
    for (uint8_t i = 0; i < num_children; ++i) {
        if (node4->keys[i] == key) {
            return node4->children + i;
        }
    }

    // not found, append child or expand node
    if (num_children < 4) {
        node4->keys[num_children] = key;
        set_num_children(cur_node_ptr, num_children + 1);
        return node4->children + num_children;
    } else {
        return node4_expand_to_node16(cur_node_ptr, node4, key);
    }
}

static node_slot_t *node16_find_or_append_child(node_slot_t *cur_node_ptr,
                                                node16_t *node16,
                                                unsigned char key,
                                                uint8_t num_children) {
    // find child
    int idx = node16_find_child_idx(node16, key, num_children);
    if (idx > 0) {
        return node16->children + _tzcnt_u32((uint32_t)idx);
    }

    // not found, append child or expand node
    if (UNLIKELY(num_children == 16)) {
        return node16_expand_to_node48(cur_node_ptr, node16, key);
    } else {
        node16->keys[num_children] = key;
        set_num_children(cur_node_ptr, num_children + 1);
        return node16->children + num_children;
    }
}

static node_slot_t *node48_find_or_append_child(node_slot_t *cur_node_ptr,
                                                node48_t *node48,
                                                unsigned char key,
                                                uint8_t num_children) {
    // find child
    uint8_t child_idx = node48->keys[key];
    if (child_idx) {
        // child found
        return node48->children + child_idx - 1;
    }

    // not found, append child or expand node
    if (UNLIKELY(num_children == 48)) {
        return node48_expand_to_node256(cur_node_ptr, node48, key);
    } else {
        uint64_t new_child_idx = _tzcnt_u64(node48->bitmap) + 1;
        node48->keys[key] = new_child_idx;
        set_num_children(cur_node_ptr, num_children + 1);
        node48->bitmap ^= (1UL << (new_child_idx - 1));
        return node48->children + new_child_idx - 1;
    }
}

static inline node_slot_t *
node256_find_or_append_child(node_slot_t *cur_node_ptr, node256_t *node256,
                             unsigned char key, uint8_t num_children) {
    // not found, append child
    if (node256->children[key] == 0) {
        set_num_children(cur_node_ptr, num_children + 1);
    }
    return node256->children + (uint8_t)key;
}

#define FIND_OR_APPEND_CHILD(N)                                                \
    {                                                                          \
        uint8_t num_children = get_num_children(*cur_node_slot_ptr);           \
        cur_node_slot_ptr = node##N##_find_or_append_child(                    \
            cur_node_slot_ptr, (node##N##_t *)raw, *key, num_children);        \
        if (key_len) {                                                         \
            ++key;                                                             \
            --key_len;                                                         \
        }                                                                      \
    }

inline void art_init(struct art *art) {
    art->root = 0;
    art->size = 0;
}

static void free_node(node_slot_t node) {
    void *raw_ptr = get_raw(node);
    switch (get_type(node)) {
    case NODE_VALUE:
        return;
    case NODE_1:
        free_node(((node1_t *)raw_ptr)->child);

        break;
    case NODE_4:
        for (int i = 0; i < get_num_children(node); ++i) {
            free_node(((node4_t *)raw_ptr)->children[i]);
        }
        break;
    case NODE_16:
        for (int i = 0; i < get_num_children(node); ++i) {
            free_node(((node16_t *)raw_ptr)->children[i]);
        }
        break;
    case NODE_48:
        for (int i = 0; i < get_num_children(node); ++i) {
            free_node(((node48_t *)raw_ptr)->children[i]);
        }
        break;
    case NODE_256:
        for (int i = 0; i < 256; ++i) {
            free_node(((node256_t *)raw_ptr)->children[i]);
        }
        break;
    }
    free(raw_ptr);
}

void art_free(struct art *art) { free_node(art->root); }

void *art_insert(struct art *restrict art, const unsigned char *restrict key,
                 size_t key_len, void *restrict value) {
    if (UNLIKELY(value == NULL)) {
        return NULL;
    }

    void *result = NULL;
    node_slot_t value_slot = ptr_to_slot(value, NODE_VALUE);
    for (node_slot_t *cur_node_slot_ptr = &art->root;;) {
        if (get_type(*cur_node_slot_ptr) != NODE_VALUE) {
            const unsigned char *prefix_key =
                get_prefix_key(*cur_node_slot_ptr);
            uint8_t prefix_key_len = get_prefix_key_len(prefix_key);

            if (prefix_key_len > 0) {
                // longest common prefix
                uint8_t mismatch_idx =
                    key_compare(&key, &key_len, prefix_key, prefix_key_len);
                if (mismatch_idx < prefix_key_len) {
                    // prefix_key: [abcde]
                    //        key: [abxyz] -> [ab][c-slot][x-slot]
                    split_prefix_key_to_node4(&cur_node_slot_ptr, prefix_key,
                                              mismatch_idx, *key);
                    if (key_len) {
                        ++key;
                        --key_len;
                    }
                    assert(get_type(*cur_node_slot_ptr) == NODE_VALUE);
                }
            }
        }
        void *raw = get_raw(*cur_node_slot_ptr);
        switch (get_type(*cur_node_slot_ptr)) {
        case NODE_VALUE: {
            if (raw != NULL && key_len > 0) {
                // cur_node: []
                // key: [abc]
                new_node4(&cur_node_slot_ptr, key, 0, (node_slot_t)NULL);
                ++key;
                --key_len;
            }
            while (key_len > MAX_PREFIX_KEY_LEN) {
                new_node1_or_assign_node_value(&cur_node_slot_ptr, key,
                                               MAX_PREFIX_KEY_LEN,
                                               (node_slot_t)NULL);
                key += MAX_PREFIX_KEY_LEN;
                key_len -= MAX_PREFIX_KEY_LEN;
            }
            raw = get_raw(*cur_node_slot_ptr);
            if (raw == NULL || key_len == 0) {
                new_node1_or_assign_node_value(&cur_node_slot_ptr, key, key_len,
                                               value_slot);
            } else {
                new_node4(&cur_node_slot_ptr, key, key_len, value_slot);
            }

            result = raw;
            goto FINAL;
        }
        case NODE_1:
            cur_node_slot_ptr = &((node1_t *)raw)->child;
            break;
        case NODE_4:
            FIND_OR_APPEND_CHILD(4);
            break;
        case NODE_16:
            FIND_OR_APPEND_CHILD(16);
            break;
        case NODE_48:
            FIND_OR_APPEND_CHILD(48);
            break;
        case NODE_256:
            FIND_OR_APPEND_CHILD(256);
            break;
        }
    }

FINAL:
    if (result == NULL) {
        ++art->size;
    }
    return result;
}

#define FIND_CHILD(N)                                                          \
    {                                                                          \
        cur_node_slot =                                                        \
            node##N##_find_child(raw, *key, get_num_children(cur_node_slot));  \
        if (key_len) {                                                         \
            ++key;                                                             \
            --key_len;                                                         \
        }                                                                      \
    }

void *art_get(struct art *art, const unsigned char *key, size_t key_len) {
    for (node_slot_t cur_node_slot = art->root; cur_node_slot;) {
        enum node_type current_type = get_type(cur_node_slot);
        if (current_type != NODE_VALUE) {
            const unsigned char *prefix_key = get_prefix_key(cur_node_slot);
            uint8_t prefix_key_len = get_prefix_key_len(prefix_key);
            if (prefix_key_len > 0) {
                uint8_t mismatch_idx =
                    key_compare(&key, &key_len, prefix_key, prefix_key_len);
                if (mismatch_idx < prefix_key_len) {
                    // prefix_key: [abcde]
                    //        key: [abxyz] -> [ab][c-slot][x-slot]
                    return NULL;
                }
            }
        }

        void *raw = get_raw(cur_node_slot);
        switch (current_type) {
        case NODE_VALUE:
            return raw;
        case NODE_1:
            cur_node_slot = ((node1_t *)raw)->child;
            break;
        case NODE_4:
            FIND_CHILD(4);
            break;
        case NODE_16:
            FIND_CHILD(16);
            break;
        case NODE_48:
            FIND_CHILD(48);
            break;
        case NODE_256:
            FIND_CHILD(256);
            break;
        }
    }
    return NULL;
}

static inline void node1_remove_child(node_slot_t *cur_node_slot_ptr, void *raw,
                                      const node_slot_t *childptr) {
    free(raw);
    // set to null
    *cur_node_slot_ptr = 0;
}

static void node4_remove_child(node_slot_t *cur_node_slot_ptr, node4_t *node4,
                               int idx, unsigned int num_children) {
    if (num_children == 1) {
        free(node4);
        *cur_node_slot_ptr = 0;
    } else {
        node4->keys[idx] = node4->keys[num_children - 1];
        node4->children[idx] = node4->children[num_children - 1];
        set_num_children(cur_node_slot_ptr, num_children - 1);
    }
}

static void node16_remove_child(node_slot_t *cur_node_slot_ptr,
                                node16_t *node16, int idx,
                                unsigned int num_children) {

    node16->keys[idx] = node16->keys[num_children - 1];
    node16->children[idx] = node16->children[num_children - 1];
    set_num_children(cur_node_slot_ptr, num_children - 1);
    if (UNLIKELY(num_children == 5)) {
        node4_t *node4 =
            calloc(sizeof(node4_t) + node16->key_len, sizeof(unsigned char));
        node4->key_len = node16->key_len;
        memcpy(node4->keys, node16->keys, sizeof(unsigned char) * 4);
        memcpy(node4->children, node16->children, sizeof(node_slot_t) * 4);
        memcpy(node4->prefix_key, node16->prefix_key, node4->key_len);
        *cur_node_slot_ptr = ptr_to_slot_num_children(node4, NODE_4, 4);
        free(node16);
    }
}

static void node48_remove_child(node_slot_t *cur_node_slot_ptr,
                                node48_t *node48, unsigned char child_key,
                                uint8_t child_idx, uint8_t num_children) {
    node48->keys[child_key] = 0;
    node48->bitmap ^= (1UL << ((uint64_t)child_idx - 1));
    set_num_children(cur_node_slot_ptr, num_children - 1);
    if (UNLIKELY(num_children == 15)) {
        node16_t *node16 =
            calloc(sizeof(node16_t) + node48->key_len, sizeof(unsigned char));
        node16->key_len = node48->key_len;
        memcpy(node16->prefix_key, node48->prefix_key, node16->key_len);
        int cnt = 0;
        for (unsigned int i = 0; i <= 255; ++i) {
            if (node48->keys[i]) {
                node16->keys[cnt] = i;
                node16->children[cnt] = node48->children[node48->keys[i] - 1];
                ++cnt;
            }
        }
        assert(cnt == 14);

        *cur_node_slot_ptr = ptr_to_slot_num_children(node16, NODE_16, 14);
        free(node48);
    }
}

static void node256_remove_child(node_slot_t *cur_node_slot_ptr,
                                 node256_t *node256, unsigned char key,
                                 uint8_t num_children) {
    node256->children[key] = 0;
    set_num_children(cur_node_slot_ptr, num_children - 1);
    if (UNLIKELY(num_children == 45)) {
        node48_t *node48 =
            calloc(sizeof(node48_t) + node256->key_len, sizeof(unsigned char));

        node48->bitmap = UINT64_MAX ^ 0xfffffffffff;
        assert(((uint64_t)&node48->keys & 0b1111) == 0);

        node48->key_len = node256->key_len;
        int cnt = 0;
        for (unsigned int i = 0; i <= 255; ++i) {
            if (node256->children[i]) {
                node48->keys[i] = ++cnt;
                node48->children[cnt - 1] = node256->children[i];
            }
        }
        assert(cnt == 44);
        memcpy(node48->prefix_key, node256->prefix_key, node48->key_len);
        *cur_node_slot_ptr = ptr_to_slot_num_children(node48, NODE_48, 44);
        free(node256);
    }
}

#define NODE4_OR_16_REMOVE_CHILD(N)                                            \
    {                                                                          \
        assert(node##N->children[idx]);                                        \
        if (key_len) {                                                         \
            ++key;                                                             \
            --key_len;                                                         \
        }                                                                      \
        enum node_type child_type = get_type(node##N->children[idx]);          \
        if (key_len == 0) {                                                    \
            if (child_type == NODE_VALUE) {                                    \
                void *result = get_raw(node##N->children[idx]);                \
                node##N##_remove_child(cur_node_slot_ptr, node##N, idx,        \
                                       num_children);                          \
                return result;                                                 \
            }                                                                  \
        } else if (child_type != NODE_VALUE) {                                 \
            void *result =                                                     \
                recursive_delete(key, key_len, &node##N->children[idx]);       \
            if (node##N->children[idx] == 0) {                                 \
                node##N##_remove_child(cur_node_slot_ptr, node##N, idx,        \
                                       num_children);                          \
            }                                                                  \
            return result;                                                     \
        }                                                                      \
    }

void *recursive_delete(const unsigned char *key, size_t key_len,
                       node_slot_t *cur_node_slot_ptr) {
    enum node_type cur_type = get_type(*cur_node_slot_ptr);
    if (cur_type != NODE_VALUE) {
        const unsigned char *prefix_key = get_prefix_key(*cur_node_slot_ptr);
        uint8_t prefix_key_len = get_prefix_key_len(prefix_key);

        if (prefix_key_len > 0) {
            // longest common prefix
            uint8_t mismatch_idx =
                key_compare(&key, &key_len, prefix_key, prefix_key_len);
            if (mismatch_idx < prefix_key_len) {
                // prefix_key: [abcde]
                //        key: [abxyz] -> [ab][c-slot][x-slot]
                return NULL;
            }
        }
    }

    void *raw = get_raw(*cur_node_slot_ptr);
    switch (cur_type) {
    case NODE_VALUE:
        clear_raw(cur_node_slot_ptr);
        return raw;
    case NODE_1: {
        node_slot_t *childptr = &((node1_t *)raw)->child;
        assert(*childptr);
        enum node_type child_type = get_type(*childptr);
        if (key_len == 0) {
            if (child_type == NODE_VALUE) {
                void *result = get_raw(*childptr);
                node1_remove_child(cur_node_slot_ptr, raw, childptr);
                return result;
            }
        } else if (child_type != NODE_VALUE) {
            void *result = recursive_delete(key, key_len, childptr);
            if (*childptr == 0) {
                node1_remove_child(cur_node_slot_ptr, raw, childptr);
            }
            return result;
        }
        return NULL;
    }
    case NODE_4: {
        node4_t *node4 = (node4_t *)raw;
        uint8_t num_children = get_num_children(*cur_node_slot_ptr);
        for (uint8_t idx = 0; idx < num_children; ++idx) {
            if (node4->keys[idx] == *key) {
                NODE4_OR_16_REMOVE_CHILD(4);
            }
        }

        // child not found
        return NULL;
    }
    case NODE_16: {
        node16_t *node16 = (node16_t *)raw;
        uint8_t num_children = get_num_children(*cur_node_slot_ptr);
        int idx = node16_find_child_idx(node16, *key, num_children);
        if (idx > 0) {
            idx = _tzcnt_u32((uint32_t)idx);
            NODE4_OR_16_REMOVE_CHILD(16);
        }
        // child not found
        return NULL;
    }
    case NODE_48: {
        node48_t *node48 = (node48_t *)raw;
        uint8_t num_children = get_num_children(*cur_node_slot_ptr);
        unsigned char child_key = *key;
        uint8_t child_idx = node48->keys[child_key];
        if (child_idx > 0) {
            unsigned int idx = child_idx - 1;
            assert(node48->children[idx]);
            if (key_len) {
                ++key;
                --key_len;
            }
            enum node_type child_type = get_type(node48->children[idx]);
            if (key_len == 0) {
                if (child_type == NODE_VALUE) {
                    void *result = get_raw(node48->children[idx]);
                    node48_remove_child(cur_node_slot_ptr, node48, child_key,
                                        child_idx, num_children);
                    return result;
                }
            } else if (child_type != NODE_VALUE) {
                void *result =
                    recursive_delete(key, key_len, &node48->children[idx]);
                if (node48->children[idx] == 0) {
                    node48_remove_child(cur_node_slot_ptr, node48, child_key,
                                        child_idx, num_children);
                }
                return result;
            }
        }
        // child not found
        return NULL;
    }
    case NODE_256: {
        node256_t *node256 = (node256_t *)raw;
        uint8_t num_children = get_num_children(*cur_node_slot_ptr);
        unsigned int idx = *key;
        if (node256->children[idx] == 0) {
            // child not found
            return NULL;
        }
        if (key_len) {
            ++key;
            --key_len;
        }
        enum node_type child_type = get_type(node256->children[idx]);
        if (key_len == 0) {
            if (child_type == NODE_VALUE) {
                void *result = get_raw(node256->children[idx]);
                node256_remove_child(cur_node_slot_ptr, node256, idx,
                                     num_children);
                return result;
            }
        } else if (child_type != NODE_VALUE) {
            void *result =
                recursive_delete(key, key_len, &node256->children[idx]);
            if (node256->children[idx] == 0) {
                node256_remove_child(cur_node_slot_ptr, node256, idx,
                                     num_children);
            }
            return result;
        }
    }
    }
}

void *art_delete(struct art *art, const unsigned char *key, size_t key_len) {
    node_slot_t *cur_node_slot_ptr = &art->root;
    void *result = recursive_delete(key, key_len, cur_node_slot_ptr);
    art->size -= (result != NULL);
    return result;
}
