// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#include <cstdint>
#include <cstring>
#include <emmintrin.h>
#include <immintrin.h>

#include "art/art.h"
#include "likely.h"

namespace ART_NAMESPACE {

AdaptiveRadixTree::NodePtr AdaptiveRadixTree::NodePtr::NewLeaf(const char *value_buf, uint8_t value_len) {
  assert(value_len < 128);
//  auto *leaf_node_ptr = reinterpret_cast<LeafNode *>(malloc(static_cast<size_t>(value_len) + 1));
//  leaf_node_ptr->has_prefix_key = false;
//  leaf_node_ptr->value_len = value_len;
//  memcpy(leaf_node_ptr->value_buffer, value_buf, value_len);
//  return AdaptiveRadixTree::NodePtr(leaf_node_ptr, NodeType::kLeafNode);
  return AdaptiveRadixTree::NodePtr();
}

AdaptiveRadixTree::NodePtr AdaptiveRadixTree::NodePtr::NewLeafWithPrefixKey(const char *prefix_key_buf,
                                                                            uint8_t key_len,
                                                                            const char *value_buf,
                                                                            uint8_t value_len) {
  assert(value_len < 128);
//  auto *leaf_node_ptr = reinterpret_cast<LeafNode *>(malloc(
//      static_cast<size_t>(key_len) +
//          static_cast<size_t>(value_len) + 2));
//  leaf_node_ptr->has_prefix_key = true;
//  leaf_node_ptr->key_len = key_len;
//  leaf_node_ptr->value_len = value_len;
//  memcpy(leaf_node_ptr->key_value_buffer, prefix_key_buf, key_len);
//  memcpy(leaf_node_ptr->key_value_buffer + key_len, value_buf, value_len);
  return AdaptiveRadixTree::NodePtr();
}

bool AdaptiveRadixTree::NodePtr::LeafMatch(uint8_t cur_key_depth,
                                           const char *key_buffer,
                                           uint8_t key_len,
                                           std::string &value_buffer) {
  assert(GetNodeType() == NodeType::kLeafNode);

//  auto leaf_node = reinterpret_cast<LeafNode *>(bits_);
//  if (leaf_node->has_prefix_key) {
//    if (leaf_node->key_len == key_len - cur_key_depth
//        && memcmp(leaf_node->key_value_buffer, key_buffer + cur_key_depth, leaf_node->key_len) == 0) {
//      auto *leaf_value_start = reinterpret_cast<uint64_t *>(leaf_partial_key_start + length);
//      char *value_ptr = reinterpret_cast<char *>(leaf_node->key_value_buffer);
//      value_buffer.assign(value_ptr);
//      return true;
//    }
//  } else if (key_len - cur_key_depth == 0) {
//    value_buffer.assign(leaf_node->value_buffer, leaf_node->value_len);
//    return true;
//  }
  return false;
}

AdaptiveRadixTree::NodePtr AdaptiveRadixTree::Node4::FindChild(partial_key_t key_span) {
//  for (int i = 0; i < count; ++i) {
//    if (partial_key[i] == key_span) {
//      return NodePtr{child_ptrs[i]};
//    }
//  }
  return AdaptiveRadixTree::NodePtr();
}

AdaptiveRadixTree::NodePtr AdaptiveRadixTree::Node16::FindChild(partial_key_t key_span) {
  __m128i key_spans = _mm_set1_epi8(key_span);
  __m128i _partial_key = _mm_load_si128(reinterpret_cast<const __m128i *>(&partial_key));
  __m128i result = _mm_cmpeq_epi8(key_spans, _partial_key);
  int mask = (1 << (count - 1)) - 1;
  int idx = _mm_movemask_epi8(result) & mask;
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
  if (UNLIKELY(root_.IsNullptr())) {
    root_ = NodePtr::NewLeafWithPrefixKey(key_buffer, key_len, value_buffer, value_len);
    return true;
  }

  return false;
}

AdaptiveRadixTree::~AdaptiveRadixTree() {
  // TODO
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

void AdaptiveRadixTree::TEST_Layout() {

  static_assert(sizeof(LeafNode) == 16);
  static_assert(sizeof(LeafNode::Data::HasPrefixKeyLayout) == 15);
  static_assert(sizeof(LeafNode::Data::NoPrefixKeyLayout) == 15);
  LeafNode leaf_node{};
  leaf_node.data.has_prefix_key_layout.key.ptr = 0xffffffffffffff;
  for (int i = 0; i < 7; ++i) {
    assert(leaf_node.data.has_prefix_key_layout.key.buf[i] == -1);
    assert(leaf_node.data.no_prefix_key_layout.value_buf8[i] == -1);
    assert(leaf_node.data.no_prefix_key_layout.value_buf15[i] == -1);
  }
  assert(leaf_node.data.no_prefix_key_layout.value_buf8[7] == 0);
  leaf_node.data.no_prefix_key_layout.value_ptr = 0xffffffffffffff;
  for (int i = 8; i < 15; ++i) {
    assert(leaf_node.data.no_prefix_key_layout.value_buf15[i] == -1);
  }
  
  static_assert(sizeof(Node4) == 40);
  static_assert(alignof(Node4) >= kMinAlignment);
  char *ptr = new char[10];
  Node4 node_4;
  memset(&node_4, 0, sizeof(node_4));
  node_4.SetPrefixKeyPtr(ptr);
  assert(node_4.GetCount() == 0);
  node_4.IncCount();
  assert(node_4.GetCount() == 1);
  node_4.IncCount();
  node_4.prefix_key_is_buf = true;
  node_4.prefix_key_len = 23;
  assert(node_4.GetCount() == 2);
  node_4.DecCount();
  assert(node_4.GetCount() == 1);
  assert(node_4.GetPrefixKeyPtr() == ptr);
  delete[]ptr;

  static_assert(sizeof(Node16) == 16 + 16 * 8 + 16);
  static_assert(alignof(Node16) == 16);
  static_assert(alignof(Node16) >= kMinAlignment);
  Node16 node_16;
  memset(&node_16, 0, sizeof(node_16));
  std::fill(node_16.prefix_key.buf14, node_16.prefix_key.buf14 + 14, -1);
  for (char i: node_16.prefix_key.buf7) {
    assert(i == -1);
  }
  assert(node_16.prefix_key.ptr == 0xffffffffffffff);

  static_assert(sizeof(Node48) == 256 + 48 * 8 + 8 + 8);
  Node48 node_48;
  node_48.key_len = 0;
  node_48.key_is_buf = 0;
  node_48.key.ptr = 0xffffffffffffff;
  node_48.key_len = 0;
  node_48.key_is_buf = 0;
  for (char i: node_48.key.buf) {
    assert(i == -1);
  }

  static_assert(sizeof(Node256) == 256 * 8 + 8);
  Node256 node_256;
  node_256.key_len = 0;
  node_256.key_is_buf = 0;
  node_256.key.ptr = 0xffffffffffffff;
  node_256.key_len = 0;
  node_256.key_is_buf = 0;
  for (char i: node_48.key.buf) {
    assert(i == -1);
  }

  static_assert(sizeof(NodePtr) == sizeof(uint64_t));
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
