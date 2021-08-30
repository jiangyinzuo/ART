// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#include "gtest/gtest.h"
#include "art/art_node.h"

using namespace ART_NAMESPACE;

namespace {

TEST(ArtNodeTest, KeyBuf) {
  static_assert(sizeof(KeyBuf) == 2);
  uint64_t place = 0;
  KeyBuf &k = reinterpret_cast<KeyBuf &>(place);
  k.SetPtr(reinterpret_cast<const char *>(UINT64_MAX));
  ASSERT_EQ(k.is_offset, 0);
  ASSERT_EQ(k.len, 0);
  k.SetPtr(nullptr);
  k.len = 123;
  ASSERT_EQ(k.GetAddr(), nullptr);
}

}
