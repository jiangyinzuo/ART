// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#include <cstdlib>

#include "gtest/gtest.h"
#include "art/art_node.h"

using namespace ART_NAMESPACE;

namespace {

TEST(ARTNodeTest, NodePtr) {
  void* node4 = malloc(sizeof(Node4));
  NodePtr p{node4, NodeType::kNode4};

  ASSERT_EQ(p.GetPtr(), node4);
  ASSERT_EQ(p.GetNodeType(), NodeType::kNode4);
  p.SetNodeType(NodeType::kNode256);
  ASSERT_EQ(p.GetPtr(), node4);
  ASSERT_EQ(p.GetNodeType(), NodeType::kNode256);
  p.SetPtr(nullptr);
  ASSERT_EQ(p.GetPtr(), nullptr);
  ASSERT_EQ(p.GetNodeType(), NodeType::kNode256);

  free(node4);
}

}