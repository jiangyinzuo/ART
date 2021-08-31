// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#include <art_node_inner.h>
#include "gtest/gtest.h"
#include "art/art_node.h"

using namespace ART_NAMESPACE;

namespace {

TEST(ArtNodeTest, Layout) {
  static_assert(sizeof(PrefixKeyValueBuf) == 0);

  auto n4 = Node4::New(ValueBufOrPtr("a", 1));
  assert((reinterpret_cast<uint64_t>(n4) & kNodeTypeMask) == 0);
  NodeFree(n4);

  static_assert(sizeof(Node4) == 48);

  static_assert(alignof(Node16) == 16);

  static_assert(sizeof(NodePtr) == sizeof(uint64_t));
  void *node4 = malloc(sizeof(Node4));

  NodePtr p{node4, NodeType::kNode4, false};

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

}
