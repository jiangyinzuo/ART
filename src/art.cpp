// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#include <cstdint>
#include <cstring>
#include <immintrin.h>

#include "art/art.h"

namespace ART_NAMESPACE {

using leaf_node_ptr_t = uint8_t *;

bool AdaptiveRadixTree::NodePtr::LeafMatch(uint8_t cur_key_depth,
                                           const char *key_buffer,
                                           uint8_t key_len,
                                           std::string &value_buffer) {
  assert(GetNodeType() == NodeType::kLeafNode);

  auto leaf_node = reinterpret_cast<leaf_node_ptr_t>(bits_);
  uint8_t length = leaf_node[0];
  if (length == key_len - cur_key_depth) {
    leaf_node_ptr_t leaf_partial_key_start = leaf_node + 1;
    if (memcmp(leaf_partial_key_start, key_buffer + cur_key_depth, length) == 0) {
      auto *leaf_value_start = reinterpret_cast<uint64_t *>(leaf_partial_key_start + length);
      char *value_ptr = reinterpret_cast<char *>(*leaf_value_start);
      value_buffer.assign(value_ptr);
      return true;
    }
  }
  return false;
}

AdaptiveRadixTree::NodePtr AdaptiveRadixTree::Node4::FindChild(partial_key_t key_span) {
  for (int i = 0; i < 4; ++i) {
    if (partial_key[i] == key_span) {
      return NodePtr{child_ptrs[i]};
    }
  }
  return AdaptiveRadixTree::NodePtr();
}

AdaptiveRadixTree::NodePtr AdaptiveRadixTree::Node16::FindChild(partial_key_t key_span) {
  __m256i key_spans = _mm256_set1_epi8(key_span);
  __m256i _partial_key = _mm256_load_si256(reinterpret_cast<__m256i *>(&partial_key));
  __m256i result = _mm256_cmpeq_epi8(key_spans, _partial_key);
  int idx = _mm256_movemask_epi8(result);
  return idx > 0 ? child_ptrs[_tzcnt_u32(static_cast<uint32_t>(idx))] : AdaptiveRadixTree::NodePtr();
}

AdaptiveRadixTree::NodePtr AdaptiveRadixTree::Node48::FindChild(partial_key_t key_span) {
  uint8_t idx = child_indexes[static_cast<uint8_t>(key_span)];
  return child_ptrs[idx];
}

AdaptiveRadixTree::NodePtr AdaptiveRadixTree::Node256::FindChild(partial_key_t key_span) {
  return child_ptrs[static_cast<uint8_t>(key_span)];
}

AdaptiveRadixTree::AdaptiveRadixTree() : root_(NodePtr()), size_(0) {}

bool AdaptiveRadixTree::Insert(const char *key_buffer,
                               uint8_t key_len,
                               const char *value_buffer,
                               size_t value_len) {
  return false;
}

bool AdaptiveRadixTree::Get(const char *key_buffer, uint8_t key_len, std::string &value_buffer) const {
  assert(key_len > 0);
  NodePtr cur_node = root_;
  size_t cur_key_depth = 0;
  while (!cur_node.IsNullptr() && cur_key_depth < key_len) {
    switch (cur_node.GetNodeType()) {
      case NodeType::kLeafNode:return cur_node.LeafMatch(cur_key_depth, key_buffer, key_len, value_buffer);
      case NodeType::kNode4: {
        auto *node4 = reinterpret_cast<Node4 *>(cur_node.GetPtr());
        cur_node = node4->FindChild(key_buffer[cur_key_depth]);
        break;
      }
      case NodeType::kNode16: {
        auto *node16 = reinterpret_cast<Node16 *>(cur_node.GetPtr());
        cur_node = node16->FindChild(key_buffer[cur_key_depth]);
        break;
      }
      case NodeType::kNode48: {
        auto *node48 = reinterpret_cast<Node48 *>(cur_node.GetPtr());
        cur_node = node48->FindChild(key_buffer[cur_key_depth]);
        break;
      }
      case NodeType::kNode256: {
        auto *node256 = reinterpret_cast<Node256 *>(cur_node.GetPtr());
        cur_node = node256->FindChild(key_buffer[cur_key_depth]);
        break;
      }
    }
    ++cur_key_depth;
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
  static_assert(alignof(Node16) == kCacheLineSize);
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
