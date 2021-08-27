// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#include <art/art.h>

#include "gtest/gtest.h"

using namespace ART_NAMESPACE;

namespace {

TEST(ARTNodeTest, Layout) {
  AdaptiveRadixTree::TEST_Layout();
}

TEST(ARTNodeTest, Get1) {
  AdaptiveRadixTree art;
  std::string buf;
  ASSERT_FALSE(art.Get("hello", 5, buf));
  ASSERT_TRUE(buf.empty());
  ASSERT_TRUE(art.Insert("hello", 5, "", 0));
  ASSERT_TRUE(art.Get("hello", 5, buf));
  ASSERT_TRUE(buf.empty());
}

TEST(ARTNodeTest, Get2) {
  AdaptiveRadixTree art;
  std::string buf;
  ASSERT_FALSE(art.Get("hello", 5, buf));
  ASSERT_TRUE(buf.empty());
  ASSERT_TRUE(art.Insert("hello", 5, "xxx", 3));
  ASSERT_TRUE(art.Get("hello", 5, buf));
  ASSERT_EQ(buf.size(), 3);
}

}