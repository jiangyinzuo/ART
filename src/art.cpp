// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#include "art/art.h"

namespace ART_NAMESPACE {

AdaptiveRadixTree::AdaptiveRadixTree() : root_(nullptr, NodeType::kNode4), size_(0) {}

bool AdaptiveRadixTree::Insert(const char *key_buffer,
                               size_t key_len,
                               const char *value_buffer,
                               size_t value_len) {
  return false;
}

bool AdaptiveRadixTree::Get(const char *key_buffer, size_t key_len, std::string &value_buffer) const {
  NodePtr cur_node = root_;
  size_t cur_key_depth = 1;
  while (!cur_node.IsNullptr()) {
    if (cur_node.GetNodeType() == NodeType::kLeafNode) {

    }
    return false;
  }
  return false;
}

bool AdaptiveRadixTree::Delete(const char *key_buffer, size_t key_len) {
  return false;
}

#ifdef ART_BUILD_TESTS
void AdaptiveRadixTree::TEST_NodePtr() {

  static_assert(sizeof(AdaptiveRadixTree::NodePtr) == sizeof(uint64_t));
  static_assert(alignof(Node4) >= kMinAlignment);
  static_assert(alignof(Node16) >= kMinAlignment);
  static_assert(alignof(Node16) >= kMinAlignment);
  static_assert(alignof(NodePtr) >= kMinAlignment);

  void *node4 = malloc(sizeof(Node4));
  NodePtr p{node4, NodeType::kNode4};

  assert(p.GetPtr() == node4);
  assert(p.GetNodeType() == NodeType::kNode4);
  p.SetNodeType(NodeType::kNode256);
  assert(p.GetPtr() == node4);
  assert(p.GetNodeType() == NodeType::kNode256);
  p.SetPtr(nullptr);
  assert(p.GetPtr() == nullptr);
  assert(p.GetNodeType() == NodeType::kNode256);
  p.SetNodeType(NodeType::kLeafNode);
  assert(p.GetNodeType() == NodeType::kLeafNode);

  free(node4);
}
#endif

}
