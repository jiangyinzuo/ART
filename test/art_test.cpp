// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#include <art/art.h>

#include "gtest/gtest.h"

using namespace ART_NAMESPACE;

namespace {

void InsertAndGet(AdaptiveRadixTree &art,
                  const char *key,
                  uint8_t key_len,
                  const char *value,
                  uint8_t value_len,
                  bool expected_insert_result) {
  ASSERT_EQ(expected_insert_result, art.Insert(key, key_len, value, value_len));
  std::string buffer(value_len, 'x');
  art.Get(key, key_len, buffer);
  const char *c = buffer.c_str();
  if (memcmp(c, value, value_len) != 0) {
    std::cerr << buffer << std::endl;
    std::cerr << value << std::endl;
    FAIL();
  }
}

TEST(ARTNodeTest, Insert1) {
  AdaptiveRadixTree art;
  std::string buf;
  ASSERT_FALSE(art.Get("hello", 5, buf));
  ASSERT_TRUE(buf.empty());
  ASSERT_FALSE(art.Insert("hello", 5, "", 0));
  ASSERT_TRUE(art.Get("hello", 5, buf));
  ASSERT_TRUE(buf.empty());
  ASSERT_FALSE(art.Get("", 0, buf));
}

TEST(ARTNodeTest, Insert2) {
  AdaptiveRadixTree art;
  std::string buf;
  ASSERT_FALSE(art.Get("hello", 5, buf));
  ASSERT_TRUE(buf.empty());
  InsertAndGet(art, "hello", 5, "xxx", 3, false);
  InsertAndGet(art, "hello", 5, "yyyy", 4, true);
  ASSERT_FALSE(art.Insert("world", 5, "a", 1));
}

TEST(ARTNodeTest, Insert3) {
  AdaptiveRadixTree art;
  std::string buf;
  ASSERT_FALSE(art.Insert("", 0, "abcde", 5));
  ASSERT_TRUE(art.Get("", 0, buf));
  ASSERT_EQ(buf.size(), 5);
  ASSERT_FALSE(art.Insert("xxx", 3, "yyy", 3));
  ASSERT_TRUE(art.Get("", 0, buf));
  ASSERT_EQ(buf.size(), 5);
}

void Insert1(AdaptiveRadixTree &art) {
  std::string buf;
  ASSERT_FALSE(art.Insert("a", 1, "abcde", 5));
  ASSERT_TRUE(art.Get("a", 1, buf));
  ASSERT_EQ(buf.size(), 5);
  ASSERT_FALSE(art.Insert("b", 3, "yyy", 3));
  ASSERT_TRUE(art.Get("a", 1, buf));
  ASSERT_EQ(buf.size(), 5);
}

TEST(ARTNodeTest, Insert4) {
  AdaptiveRadixTree art;
  Insert1(art);
  art.Insert("", 0, "header", 6);
  std::string buffer;
  ASSERT_TRUE(art.Get("", 0, buffer));
  ASSERT_EQ(buffer, "header");
}

TEST(ARTNodeTest, Insert5) {
  AdaptiveRadixTree art;
  art.Insert("", 0, "header", 6);
  Insert1(art);
  std::string buffer;
  ASSERT_TRUE(art.Get("", 0, buffer));
  ASSERT_EQ(buffer, "header");
}

TEST(ARTNodeTest, Insert6) {
  AdaptiveRadixTree art;
  art.Insert("", 0, "header", 6);
  std::string buffer;

  const char *a[][2] = {{"aaaaa", "aaaaaa"}, {"bbbbb", "bbbbbb"}, {"ccccc", "cccccc"}, {"ddddd", "dddddd"}};
  for (auto s: a) {
    InsertAndGet(art, s[0], 5, s[1], 6, false);
  }

  for (auto s: a) {
    art.Get(s[0], 5, buffer);
    ASSERT_EQ(buffer, s[1]);
  }

  ASSERT_TRUE(art.Get("", 0, buffer));
  ASSERT_EQ(buffer, "header");
}

TEST(ARTNodeTest, InsertNode4WithPrefixKey) {
  AdaptiveRadixTree art;
  InsertAndGet(art, "world", 5, "apple", 5, false);
  InsertAndGet(art, "wolf", 4, "orange", 6, false);
  InsertAndGet(art, "", 0, "header1", 7, false);
  InsertAndGet(art, "", 0, "hello world!!!", 14, true);
  InsertAndGet(art, "wo", 2, "banana", 6, false);
  InsertAndGet(art, "wo", 2, "watermelon", 10, true);
}

}