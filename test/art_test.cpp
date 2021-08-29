// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#include <art/art.h>

#include "gtest/gtest.h"

using namespace ART_NAMESPACE;

namespace {

TEST(ARTNodeTest, Layout) {
  auto leaf = new LeafNodeWithPrefixKey("", 0, "", 0, BufOrPtr());
  assert((reinterpret_cast<uint64_t>(leaf) & 0b1111) == 0);
  delete leaf;

  auto n4 = new Node4WithPrefixKey("a", 1);
  assert((reinterpret_cast<uint64_t>(n4) & 0b1111) == 0);
  delete n4;

  auto n16 = new Node16;
  assert((reinterpret_cast<uint64_t>(n16) & 0b1111) == 0);
  delete n16;

  auto n48 = new Node48;
  assert((reinterpret_cast<uint64_t>(n48) & 0b1111) == 0);
  delete n48;

  auto n256 = new Node256;
  assert((reinterpret_cast<uint64_t>(n256) & 0b1111) == 0);
  delete n256;

  static_assert(sizeof(Node4) == 48);

  static_assert(sizeof(LeafNodeWithPrefixKey) == 24);

  static_assert(sizeof(Node4WithPrefixKey) == 64);

  // It is Node4WithPrefixKey's responsibility to free "ptr".
  char *ptr = new char[10];
  Node4WithPrefixKey node_4("a", 1);
  memset(&node_4, 0, sizeof(node_4));
  node_4.SetPrefixKeyPtr(ptr);
  assert(node_4.GetCount() == 0);
  node_4.IncCount();
  assert(node_4.GetCount() == 1);
  node_4.IncCount();
  node_4.prefix_key_len = 23;
  assert(node_4.GetCount() == 2);
  node_4.DecCount();
  assert(node_4.GetCount() == 1);
  assert(node_4.GetPrefixKeyPtr() == ptr);

  static_assert(sizeof(Node16) == 16 + 16 * 8 + 16);
  static_assert(alignof(Node16) == 16);

  static_assert(sizeof(Node48) == 256 + 48 * 8 + 8 + 16);

  static_assert(sizeof(Node256) == 256 * 8 + 16);

  static_assert(sizeof(NodePtr) == sizeof(uint64_t));
  void *node4 = malloc(sizeof(Node4WithPrefixKey));

  NodePtr p{node4, NodeType::kNode4};

  assert(p.GetPtr<void *>() == node4);
  assert(p.GetNodeType() == NodeType::kNode4);
  p.SetNodeType(NodeType::kNode256);
  assert(p.GetPtr<void *>() == node4);
  assert(p.GetNodeType() == NodeType::kNode256);
  p.SetPtr(nullptr);
  assert(p.GetPtr<void *>() == nullptr);
  assert(p.GetNodeType() == NodeType::kNode256);
  p.SetNodeType(NodeType::kInlineLeafNode);
  assert(p.GetNodeType() == NodeType::kInlineLeafNode);
  p.TEST_Layout();
  free(node4);
}

TEST(ARTNodeTest, Insert1) {
  AdaptiveRadixTree art;
  std::string buf;
  ASSERT_FALSE(art.Get("hello", 5, buf));
  ASSERT_TRUE(buf.empty());
  ASSERT_FALSE(art.Insert("hello", 5, "", 0));
  ASSERT_TRUE(art.Get("hello", 5, buf));
  ASSERT_TRUE(buf.empty());
}

TEST(ARTNodeTest, Insert2) {
  AdaptiveRadixTree art;
  std::string buf;
  ASSERT_FALSE(art.Get("hello", 5, buf));
  ASSERT_TRUE(buf.empty());
  ASSERT_FALSE(art.Insert("hello", 5, "xxx", 3));
  ASSERT_TRUE(art.Get("hello", 5, buf));
  ASSERT_EQ(buf.size(), 3);
  ASSERT_TRUE(art.Insert("hello", 5, "yyyy", 4));
  ASSERT_TRUE(art.Get("hello", 5, buf));
  ASSERT_EQ(buf.size(), 4);
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

}