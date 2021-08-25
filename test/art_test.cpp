// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#include <art/art.h>

#include "gtest/gtest.h"

using namespace ART_NAMESPACE;

namespace {

TEST(ARTNodeTest, NodePtr) {
  AdaptiveRadixTree::TEST_NodePtr();
}

TEST(ARTNodeTest, Get) {
  AdaptiveRadixTree art;
  std::string buf;
  ASSERT_FALSE(art.Get("hello", 5, buf));
  ASSERT_TRUE(buf.empty());
}

}