// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.
#include "art/art.h"
#include "gtest/gtest.h"

namespace {

TEST(ARTTest, Insert) {
    struct art a;
    art_init(&a);
    ASSERT_EQ(a.root, 0);
    std::string value;
    value.assign("hello");
    ASSERT_EQ(art_insert(&a, "hello", 5, (void *)value.c_str()), nullptr);
}

void insert_and_get(struct art *a, const char *key, uint8_t key_len,
                    void *value, void *expected_insert_result) {
    ASSERT_EQ(expected_insert_result, art_insert(a, key, key_len, value));
    ASSERT_EQ(art_get(a, key, key_len), value);
}

TEST(ARTNodeTest, Insert1) {
    struct art a;
    art_init(&a);
    ASSERT_EQ(art_get(&a, "hello", 5), nullptr);
    insert_and_get(&a, "hello", 5, nullptr, nullptr);
    ASSERT_EQ(art_get(&a, "", 0), nullptr);
}

TEST(ARTNodeTest, Insert2) {
    struct art a;
    art_init(&a);
    ASSERT_EQ(art_get(&a, "hello", 5), nullptr);
    insert_and_get(&a, "hello", 5, (void *)0xff00, nullptr);
    insert_and_get(&a, "hello", 5, (void *)0xf200, (void *)0xff00);
    ASSERT_EQ(art_insert(&a, "world", 5, (void *)0xfff0), nullptr);
}

TEST(ARTNodeTest, Insert3) {
    struct art a;
    art_init(&a);
    insert_and_get(&a, "", 0, (void *)0xf0, nullptr);
    insert_and_get(&a, "abc", 3, (void *)0xe0, nullptr);
    ASSERT_EQ(art_get(&a, "", 0), (void *)0xf0);
}

void Insert1(struct art *a) {
    insert_and_get(a, "a", 1, (void *)0xff0, nullptr);
    insert_and_get(a, "b", 1, (void *)0xff20, nullptr);
    insert_and_get(a, "b", 1, (void *)0xff30, (void *)0xff20);
}

TEST(ARTNodeTest, Insert4) {
    struct art a;
    art_init(&a);
    Insert1(&a);
    insert_and_get(&a, "", 0, (void *)0xfff0, nullptr);
}

TEST(ARTNodeTest, Insert5) {
    struct art a;
    art_init(&a);
    art_insert(&a, "", 0, (void *)0x12370);
    Insert1(&a);
    ASSERT_EQ(art_get(&a, "", 0), (void *)0x12370);
}

TEST(ARTNodeTest, Insert6) {
    struct art a;
    art_init(&a);
    art_insert(&a, "", 0, (void *)0x12370);

    void *arr[][2] = {{(void *)"aaaaa", (void *)0x1230},
                      {(void *)"bbbbb", (void *)0x1240},
                      {(void *)"ddddd", (void *)0x1210}};
    for (auto s : arr) {
        insert_and_get(&a, (const char *)s[0], 5, s[1], nullptr);
    }

    for (auto s : arr) {
        ASSERT_EQ(art_get(&a, (const char *)s[0], 5), s[1]);
    }

    ASSERT_EQ(art_get(&a, "", 0), (void *)0x12370);
    insert_and_get(&a, "ccccc", 5, (void *)0x6660, nullptr);
}

TEST(ARTNodeTest, InsertNode4WithPrefixKey) {
    struct art a;
    art_init(&a);
    insert_and_get(&a, "world", 5, (void *)0x10, nullptr);
    insert_and_get(&a, "wolf", 4, (void *)0x20, nullptr);
    insert_and_get(&a, "", 0, (void *)0x30, nullptr);
    insert_and_get(&a, "", 0, (void *)0x40, (void *)0x30);
    insert_and_get(&a, "wo", 2, (void *)0x50, nullptr);
    insert_and_get(&a, "wo", 2, (void *)0x60, (void *)0x50);
}

} // namespace