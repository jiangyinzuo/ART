// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#include <fstream>
#include <map>
#include <string>

#include "art/art.h"
#include "gtest/gtest.h"

namespace {

TEST(ARTTest, Insert0) {
    struct art a;
    art_init(&a);
    ASSERT_EQ(a.root, 0);
    std::string value;
    value.assign("hello");
    ASSERT_EQ(art_insert(&a, reinterpret_cast<const unsigned char *>("hello"),
                         5, (void *)value.c_str()),
              nullptr);
    art_free(&a);
}

void insert_and_get(struct art *a, const char *key, uint8_t key_len,
                    void *value, void *expected_insert_result) {
    ASSERT_EQ(expected_insert_result,
              art_insert(a, reinterpret_cast<const unsigned char *>(key),
                         key_len, value));
    ASSERT_EQ(art_get(a, reinterpret_cast<const unsigned char *>(key), key_len),
              value);
}

TEST(ARTTest, Insert1) {
    struct art a;
    art_init(&a);
    ASSERT_EQ(art_get(&a, reinterpret_cast<const unsigned char *>("hello"), 5),
              nullptr);
    insert_and_get(&a, "hello", 5, nullptr, nullptr);
    ASSERT_EQ(art_get(&a, reinterpret_cast<const unsigned char *>(""), 0),
              nullptr);
    insert_and_get(&a, "hello", 5, (void *)0x770, nullptr);
    ASSERT_EQ(art_get(&a, reinterpret_cast<const unsigned char *>("hello"), 5),
              (void *)0x770);
    insert_and_get(&a, "hey", 3, (void *)0x880, nullptr);
    ASSERT_EQ(art_get(&a, reinterpret_cast<const unsigned char *>("hello"), 5),
              (void *)0x770);
    ASSERT_EQ(art_get(&a, reinterpret_cast<const unsigned char *>("hey"), 3),
              (void *)0x880);
    art_free(&a);
}

TEST(ARTTest, Insert2) {
    struct art a;
    art_init(&a);
    ASSERT_EQ(art_get(&a, reinterpret_cast<const unsigned char *>("hello"), 5),
              nullptr);
    insert_and_get(&a, "hello", 5, (void *)0xff00, nullptr);
    insert_and_get(&a, "hello", 5, (void *)0xf200, (void *)0xff00);
    ASSERT_EQ(art_insert(&a, reinterpret_cast<const unsigned char *>("world"),
                         5, (void *)0xfff0),
              nullptr);
    art_free(&a);
}

TEST(ARTTest, Insert3) {
    struct art a;
    art_init(&a);
    insert_and_get(&a, "", 0, (void *)0xf0, nullptr);
    insert_and_get(&a, "abc", 3, (void *)0xe0, nullptr);
    ASSERT_EQ(art_get(&a, reinterpret_cast<const unsigned char *>(""), 0),
              (void *)0xf0);
    art_free(&a);
}

void Insert1(struct art *a) {
    insert_and_get(a, "a", 1, (void *)0xff0, nullptr);
    insert_and_get(a, "b", 1, (void *)0xff20, nullptr);
    insert_and_get(a, "b", 1, (void *)0xff30, (void *)0xff20);
}

TEST(ARTTest, Insert4) {
    struct art a;
    art_init(&a);
    Insert1(&a);
    insert_and_get(&a, "", 0, (void *)0xfff0, nullptr);
    art_free(&a);
}

TEST(ARTTest, Insert5) {
    struct art a;
    art_init(&a);
    art_insert(&a, reinterpret_cast<const unsigned char *>(""), 0,
               (void *)0x12370);
    Insert1(&a);
    ASSERT_EQ(art_get(&a, reinterpret_cast<const unsigned char *>(""), 0),
              (void *)0x12370);
    art_free(&a);
}

TEST(ARTTest, Insert6) {
    struct art a;
    art_init(&a);
    art_insert(&a, reinterpret_cast<const unsigned char *>(""), 0,
               (void *)0x12370);

    void *arr[][2] = {{(void *)"aaaaa", (void *)0x1230},
                      {(void *)"bbbbb", (void *)0x1240},
                      {(void *)"ddddd", (void *)0x1210}};
    for (auto s : arr) {
        insert_and_get(&a, (const char *)s[0], 5, s[1], nullptr);
    }

    for (auto s : arr) {
        ASSERT_EQ(
            art_get(&a,
                    reinterpret_cast<const unsigned char *>((const char *)s[0]),
                    5),
            s[1]);
    }

    ASSERT_EQ(art_get(&a, reinterpret_cast<const unsigned char *>(""), 0),
              (void *)0x12370);
    insert_and_get(&a, "ccccc", 5, (void *)0x6660, nullptr);
    art_free(&a);
}

TEST(ARTTest, Insert7) {
    struct art a;
    art_init(&a);
    art_insert(&a, reinterpret_cast<const unsigned char *>(""), 0,
               (void *)0x6660);
    ASSERT_EQ(art_get(&a, reinterpret_cast<const unsigned char *>("abc"), 3),
              nullptr);
    ASSERT_EQ(art_delete(&a, reinterpret_cast<const unsigned char *>("abc"), 3),
              nullptr);
    ASSERT_EQ(art_get(&a, reinterpret_cast<const unsigned char *>(""), 0),
              (void *)0x6660);

    art_free(&a);
}

void TestSplitKey(const char *keys[], size_t len) {
    struct art a;
    art_init(&a);
    unsigned long value = 1;
    for (size_t i = 0; i < len; ++i) {
        insert_and_get(&a, keys[i], strlen(keys[i]), (void *)(value++ << 8),
                       nullptr);
    }
    value = 1;
    for (size_t i = 0; i < len; ++i) {
        ASSERT_EQ(art_get(&a, reinterpret_cast<const unsigned char *>(keys[i]),
                          strlen(keys[i])),
                  (void *)(value++ << 8));
    }
    art_free(&a);
}

TEST(ARTTest, SplitPrefixKey) {
    static const char *keys1[7] = {"hungeringly", "hungerless", "hungerly",
                                   "hungerproof", "hungerweed", "hungrify",
                                   "hungrily"};
    static const char *keys2[4] = {"hungrify", "hungrily", "hungriness",
                                   "hungry"};
    TestSplitKey(keys1, 7);
    TestSplitKey(keys2, 4);
}

TEST(ARTTest, InsertNode4) {
    struct art a;
    art_init(&a);
    insert_and_get(&a, "world", 5, (void *)0x10, nullptr);
    insert_and_get(&a, "wolf", 4, (void *)0x20, nullptr);
    insert_and_get(&a, "", 0, (void *)0x30, nullptr);
    insert_and_get(&a, "", 0, (void *)0x40, (void *)0x30);
    insert_and_get(&a, "wo", 2, (void *)0x50, nullptr);
    insert_and_get(&a, "wo", 2, (void *)0x60, (void *)0x50);
    art_free(&a);
}

TEST(ARTTest, InsertNode48) {
    struct art a;
    art_init(&a);
    char key[48][4];
    for (char i = 0; i < 48; ++i) {
        key[i][0] = 'a';
        key[i][1] = 'b';
        key[i][2] = i + (char)1;
        key[i][3] = '\0';
    }
    for (int times = 0; times < 4; ++times) {
        for (unsigned long i = 0; i < 48; ++i) {
            insert_and_get(&a, &key[i][0], 3, (void *)((i + 1) << 8),
                           times ? (void *)((i + 1) << 8) : nullptr);
            ASSERT_EQ(a.size, times ? 48 : i + 1);
        }
        for (unsigned long i = 0; i < 48; ++i) {
            ASSERT_EQ(
                art_get(&a, reinterpret_cast<const unsigned char *>(&key[i][0]),
                        3),
                (void *)((i + 1) << 8));
        }
    }
    art_free(&a);
}

TEST(ARTTest, InsertNode256) {
    struct art a;
    art_init(&a);
    static char key[256][4];
    for (unsigned int i = 0; i <= 255; ++i) {
        key[i][0] = 'a';
        key[i][1] = 'b';
        key[i][2] = i;
        key[i][3] = '\0';
    }

    for (int times = 0; times < 4; ++times) {
        for (unsigned long i = 0; i < 256; ++i) {
            insert_and_get(&a, &key[i][0], 3, (void *)((i + 1) << 8),
                           times ? (void *)((i + 1) << 8) : nullptr);
            ASSERT_EQ(a.size, times ? 256 : i + 1);
        }
        for (unsigned long i = 0; i < 256; ++i) {
            ASSERT_EQ(
                art_get(&a, reinterpret_cast<const unsigned char *>(&key[i][0]),
                        3),
                (void *)((i + 1) << 8));
        }
    }
    art_free(&a);
}

TEST(ARTTest, InsertLongKey) {
    struct art a;
    art_init(&a);
    insert_and_get(&a, "abcdefghijklmnopqrstuvwxyz", 26, (void *)0x567800,
                   nullptr);
    insert_and_get(&a, "abcdefghijklmnopqrstuvwxyz", 26, (void *)0x888800,
                   (void *)0x567800);
    insert_and_get(&a, "abcdEFGHIJKLMNOPQRSTUVWXYZ", 26, (void *)0x7770,
                   nullptr);
    ASSERT_EQ(art_get(&a,
                      reinterpret_cast<const unsigned char *>(
                          "abcdefghijklmnopqrstuvwxyz"),
                      26),
              (void *)0x888800);
    insert_and_get(&a, "", 0, (void *)0xabcd00, nullptr);
    ASSERT_EQ(art_get(&a,
                      reinterpret_cast<const unsigned char *>(
                          "abcdefghijklmnopqrstuvwxyz"),
                      26),
              (void *)0x888800);
    ASSERT_EQ(a.size, 3);
    ASSERT_EQ(
        art_delete(&a, reinterpret_cast<const unsigned char *>("abcde"), 5),
        nullptr);
    art_free(&a);
}

TEST(ARTTest, Delete0) {
    struct art a;
    art_init(&a);
    ASSERT_EQ(art_delete(&a, reinterpret_cast<const unsigned char *>(""), 0),
              nullptr);
    insert_and_get(&a, "", 0, (void *)0xabc00, nullptr);
    insert_and_get(&a, "", 0, (void *)0xabc00, (void *)0xabc00);
    ASSERT_EQ(art_delete(&a, reinterpret_cast<const unsigned char *>(""), 0),
              (void *)0xabc00);
    ASSERT_EQ(art_get(&a, reinterpret_cast<const unsigned char *>(""), 0),
              nullptr);
    art_free(&a);
}

int art_count_cb(void *data, const unsigned char *key, uint32_t key_len, void *value) {
    ++(*(uint64_t *)data);
    return 0;
}

int art_count_value_cb(void *data, void *value) {
    ++(*(uint64_t *)data);
    return 0;
}

void Delete(char key[256][5], int tree_size) {
    struct art a;
    art_init(&a);
    for (unsigned long i = 0; i < tree_size; ++i) {
        insert_and_get(&a, &key[i][0], 4, (void *)((i + 1) << 8), nullptr);
    }
    ASSERT_EQ(a.size, tree_size);
    ASSERT_NE(a.root, 0);

    // test iter value
    uint64_t count = 0;
    art_iter_value(&a, art_count_value_cb, &count);
    ASSERT_EQ(count, tree_size);

    // test iter
    count = 0;
    art_iter(&a, art_count_cb, &count);
    ASSERT_EQ(count, tree_size);

    count = 0;
    art_iter_value_prefix(&a, reinterpret_cast<const unsigned char *>("a"), 1,
                          art_count_value_cb, &count);
    ASSERT_EQ(count, tree_size);
    count = 0;
    art_iter_value_prefix(&a, reinterpret_cast<const unsigned char *>("z"), 1,
                          art_count_value_cb, &count);
    ASSERT_EQ(count, 0);
    art_iter_value_prefix(&a, reinterpret_cast<const unsigned char *>("xz"), 1,
                          art_count_value_cb, &count);
    ASSERT_EQ(count, 0);

    for (unsigned long i = 0; i < tree_size; ++i) {
        ASSERT_EQ(
            art_delete(&a, reinterpret_cast<const unsigned char *>(&key[i][0]),
                       4),
            (void *)((i + 1) << 8));
        ASSERT_EQ(
            art_delete(&a, reinterpret_cast<const unsigned char *>(&key[i][0]),
                       4),
            nullptr);
        ASSERT_EQ(
            art_get(&a, reinterpret_cast<const unsigned char *>(&key[i][0]), 4),
            nullptr);
    }
    ASSERT_EQ(a.size, 0);
    ASSERT_EQ(a.root, 0);
    art_free(&a);
}

TEST(ARTTest, Delete1) {
    static char keys1[256][5];
    static char keys2[455][5];
    keys1[0][0] = keys2[0][0] = 'a';
    keys1[0][1] = keys2[0][1] = 'b';
    keys1[0][2] = keys2[0][1] = 'g';
    keys1[0][3] = keys2[0][1] = 'g';
    keys1[0][4] = keys2[0][1] = '\0';
    for (unsigned int i = 1; i <= 255; ++i) {
        keys1[i][0] = keys2[i][0] = 'a';
        keys1[i][1] = keys2[i][1] = 'b';
        keys1[i][2] = keys2[i][2] = i;
        keys1[i][3] = keys2[i][3] = 'x';
        keys1[i][4] = keys2[i][4] = '\0';
    }
    for (unsigned int i = 256; i < 455; ++i) {
        keys2[i][0] = 'a';
        keys2[i][1] = i - 255;
        keys2[i][2] = i - 255;
        keys2[i][3] = 'z';
        keys2[i][4] = '\0';
    }

    Delete(keys1, 4);
    Delete(keys1, 16);
    Delete(keys1, 48);
    Delete(keys1, 256);
    Delete(keys2, 455);
}

TEST(ARTTest, IterValuePrefixWords0) {
    struct art a;
    art_init(&a);

    std::ifstream f("test_data/words0.txt");
    std::map<std::string, void *> m;
    unsigned long line = 0;
    uint64_t expected_hu_count = 0, expected_a_count = 0;
    while (f.peek() != EOF) {
        std::string buf;
        f >> buf;

        if (strncmp(buf.c_str(), "hu", 2) == 0) {
            ++expected_hu_count;
        } else if (strncmp(buf.c_str(), "a", 1) == 0) {
            ++expected_a_count;
        }

        insert_and_get(&a, buf.c_str(), buf.size(), (void *)((++line) << 8),
                       nullptr);

        std::map<std::string, void *> fail_map;
        m[buf] = reinterpret_cast<void *>(line << 8);
        for (auto &[k, v] : m) {
            std::cout << k << " " << v << '\n';
            void *result =
                art_get(&a, reinterpret_cast<const unsigned char *>(k.c_str()),
                        k.size());
            if (result != v) {
                fail_map[k] = result;
            }
        }
        if (!fail_map.empty()) {
            std::cout << "after inserting " << buf << ", " << fail_map.size()
                      << " failed!!" << '\n';
            for (auto &[fk, fv] : fail_map) {
                std::cout << ' ' << fk << ' ' << fv << '\n';
            }
            FAIL();
        }
        std::cout << "-------" << std::endl;
    }
    ASSERT_EQ(line, a.size);

    uint64_t actual_hu_count = 0;
    art_iter_value_prefix(&a, reinterpret_cast<const unsigned char *>("hu"), 2,
                          art_count_value_cb, &actual_hu_count);
    ASSERT_EQ(expected_hu_count, actual_hu_count);

    uint64_t actual_a_count = 0;
    art_iter_value_prefix(&a, reinterpret_cast<const unsigned char *>("a"), 2,
                          art_count_value_cb, &actual_a_count);
    ASSERT_EQ(expected_hu_count, actual_hu_count);

    uint64_t count = 0;
    art_iter_value(&a, art_count_value_cb, &count);
    ASSERT_EQ(count, m.size());

    f.close();
    art_free(&a);
}

} // namespace