// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#include "gtest/gtest.h"
#include "art/art_namespace.h"
#include "util.h"

using namespace ART_NAMESPACE;

namespace {

TEST(UtilTest, MemCmpMismatch) {
  ASSERT_EQ(MemCmpMismatch("hello", "hello", 5), 5);
  ASSERT_EQ(MemCmpMismatch("xello", "hello", 5), 0);
  ASSERT_EQ(MemCmpMismatch("apple", "app", 3), 3);
  ASSERT_EQ(MemCmpMismatch("app", "api", 3), 2);
}

}
