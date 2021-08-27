// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#include <cstdint>
#include <cstring>
#include <emmintrin.h>
#include <immintrin.h>

#include "art/art.h"
#include "likely.h"
#include "util.h"

namespace ART_NAMESPACE {

AdaptiveRadixTree::NodePtr AdaptiveRadixTree::NodePtr::NewLeaf(const char *value_buf, uint8_t value_len) {
  assert(value_len < 128);
  auto *leaf_node_ptr = new LeafNode;
  leaf_node_ptr->no_partial_key = true;

  leaf_node_ptr->value_len = value_len;
  if (value_len <= 15) {
    // inline value
    memcpy(leaf_node_ptr->value_buf15, value_buf, value_len);
  } else {
    memcpy(leaf_node_ptr->value_buf8, value_buf, 8);
    char *value_ptr = new char[value_len - 8];
    memcpy(value_ptr, value_buf + 8, value_len - 8);
    leaf_node_ptr->value_ptr = reinterpret_cast<uint64_t>(value_ptr);
  }

  return AdaptiveRadixTree::NodePtr(leaf_node_ptr, NodeType::kLeafNode);
}

AdaptiveRadixTree::NodePtr AdaptiveRadixTree::NodePtr::NewLeaf(const partial_key_t *prefix_key_buf,
                                                               uint8_t prefix_key_len,
                                                               const char *value_buf,
                                                               uint8_t value_len) {
  assert(prefix_key_len < 128);
  assert(value_len < 128);
  auto *leaf_node_ptr = new LeafNode;

  // initialize key
  leaf_node_ptr->no_partial_key = false;
  leaf_node_ptr->partial_key_len = prefix_key_len;
  if (prefix_key_len <= 7) {
    memcpy(leaf_node_ptr->key.buf, prefix_key_buf, prefix_key_len);
  } else {
    auto *key_ptr = new partial_key_t[prefix_key_len];
    assert((reinterpret_cast<uint64_t>(key_ptr) && 0xff00000000000000) == 0);
    memcpy(key_ptr, prefix_key_buf, prefix_key_len);
    leaf_node_ptr->key.ptr = reinterpret_cast<uint64_t>(key_ptr);
  }

  // initialize value
  leaf_node_ptr->value_len = value_len;
  if (value_len <= 7) {
    // inline value
    memcpy(leaf_node_ptr->value7.buf, value_buf, value_len);
  } else {
    auto *value_ptr = new char[value_len];
    assert((reinterpret_cast<uint64_t>(value_ptr) && 0xff00000000000000) == 0);
    memcpy(value_ptr, value_buf, value_len);
    leaf_node_ptr->value7.ptr = reinterpret_cast<uint64_t>(value_ptr);
  }

  return AdaptiveRadixTree::NodePtr(leaf_node_ptr, NodeType::kLeafNode);
}

bool AdaptiveRadixTree::LeafNode::Insert(const partial_key_t *partial_key_buffer,
                                         uint8_t partial_key_len,
                                         const char *value_buffer,
                                         uint8_t value_len,
                                         NodePtr &cur_node) {
  if (no_partial_key) {
    if (partial_key_len == 0) {
      // directly update value
      UpdateNoPartialKey(value_buffer, value_len);
      return true;
    }
  } else {
    // TODO
    if (IsInlineKey()) {
      if (this->partial_key_len == partial_key_len) {
        int mis_match_idx = MemCmpMismatch(key.buf, partial_key_buffer, partial_key_len);
        if (mis_match_idx == partial_key_len) {
          // these two partial_keys are equal.
          UpdateHasPartialKey(value_buffer, value_len);
          return true;
        } else if (mis_match_idx == 0) {
          auto node4 = new Node4;

          cur_node = NodePtr(node4, NodeType::kNode4);
          return false;
        }
        // TODO
      } else if (this->partial_key_len > partial_key_len) {

      } else {

      }

    } else {

    }
  }
  return false;
}

bool AdaptiveRadixTree::LeafNode::GetIfMatch(uint8_t key_compared,
                                             const partial_key_t *key_buffer,
                                             uint8_t key_len,
                                             std::string &value_buffer) const {
  if (no_partial_key) {
    if (key_len == key_compared) {
      GetNoPartialKey(value_buffer);
      return true;
    }
  } else if (key_compared + partial_key_len == key_len) {
    if (IsInlineKey()) {
      if (memcmp(key.buf, key_buffer + key_compared, partial_key_len) == 0) {
        GetHasPartialKey(value_buffer);
        return true;
      }
    } else if (memcmp(reinterpret_cast<void *>(key.ptr), key_buffer + key_compared, partial_key_len) == 0) {
      GetHasPartialKey(value_buffer);
      return true;
    }
  }
  return false;
}

void AdaptiveRadixTree::LeafNode::UpdateNoPartialKey(const char *value_buffer, uint8_t value_len) {
  if (this->value_len > 15) {
    delete[] reinterpret_cast<char *>(value_ptr);
  }

  if (value_len <= 15) {
    memcpy(value_buf15, value_buffer, value_len);
  } else {
    memcpy(value_buf8, value_buffer, 8);
    char *new_value_ptr = new char[value_len - 8];
    memcpy(new_value_ptr, value_buffer + 8, value_len - 8);
    value_ptr = reinterpret_cast<uint64_t>(new_value_ptr);
  }
  this->value_len = value_len;
}

void AdaptiveRadixTree::LeafNode::UpdateHasPartialKey(const char *value_buffer, uint8_t value_len) {
  if (this->value_len > 7) {
    delete reinterpret_cast<char *>(value7.ptr);
  }

  if (value_len <= 7) {
    memcpy(value7.buf, value_buffer, value_len);
  } else {
    char *new_value_ptr = new char[value_len];
    memcpy(new_value_ptr, value_buffer, value_len);
    value7.ptr = reinterpret_cast<uint64_t>(new_value_ptr);
  }
  this->value_len = value_len;
}

void AdaptiveRadixTree::LeafNode::GetNoPartialKey(std::string &value_buffer) const {
  if (value_len <= 15) {
    value_buffer.assign(value_buf15, value_len);
  } else {
    value_buffer.assign(value_buf8, 8);
    value_buffer.append(reinterpret_cast<char *>(value_ptr), value_len - 8);
  }
}

inline void AdaptiveRadixTree::LeafNode::GetHasPartialKey(std::string &value_buffer) const {
  value_buffer.assign(value_len <= 7 ? value7.buf : reinterpret_cast<char *>(value7.ptr), value_len);
}

AdaptiveRadixTree::Node4::Node4(const char *prefix_key_buf, uint8_t prefix_key_len)
    : __prefix_key_ptr_count(0), prefix_key_len(prefix_key_len) {
  assert(prefix_key_len < 128);
  if (prefix_key_len <= 10) {
    memcpy(prefix_key_buf10, prefix_key_buf, prefix_key_len);
  } else {
    memcpy(prefix_key_buf4, prefix_key_buf, 4);
    char *ptr = new char[prefix_key_len - 4];
    SetPrefixKeyPtr(ptr);
  }
}

AdaptiveRadixTree::Node4::~Node4() {
  if (prefix_key_len > 10) {
    delete[] GetPrefixKeyPtr();
  }
}

AdaptiveRadixTree::NodePtr AdaptiveRadixTree::Node4::FindChild(partial_key_t key_span) {
  for (int i = 0; i < GetCount(); ++i) {
    if (partial_key[i] == key_span) {
      return NodePtr{child_ptrs[i]};
    }
  }
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

bool AdaptiveRadixTree::Insert(const partial_key_t *key_buffer,
                               uint8_t key_len,
                               const char *value_buffer,
                               uint8_t value_len) {
  assert(key_len < 128);
  assert(value_len < 128);

  if (UNLIKELY(root_.IsNullptr())) {
    root_ = NodePtr::NewLeaf(key_buffer, key_len, value_buffer, value_len);
    return false;
  }

  NodePtr &cur_node = root_;

  do {
    switch (cur_node.GetNodeType()) {
      case NodeType::kLeafNode: {
        auto leaf_node = cur_node.ToLeafNode();
        return leaf_node->Insert(key_buffer, key_len, value_buffer, value_len, cur_node);
      }
      case NodeType::kNode4:break;
      case NodeType::kNode16:break;
      case NodeType::kNode48:break;
      case NodeType::kNode256:break;
    }
  } while (!cur_node.IsNullptr());
  return false;
}

AdaptiveRadixTree::~AdaptiveRadixTree() {
  // TODO
}

bool AdaptiveRadixTree::Get(const char *key_buffer, uint8_t key_len, std::string &value_buffer) const {
  assert(key_len > 0);
  if (UNLIKELY(key_len >= 128)) {
    return false;
  }

  NodePtr cur_node = root_;
  size_t cur_key_depth = 0;
  while (!cur_node.IsNullptr() && cur_key_depth < key_len) {
    switch (cur_node.GetNodeType()) {
      case NodeType::kLeafNode: {
        auto leaf_node = cur_node.ToLeafNode();
        return leaf_node->GetIfMatch(cur_key_depth, key_buffer, key_len, value_buffer);
      }
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
  LeafNode leaf_node{};
  leaf_node.key.ptr = 0xffffffffffffff;
  for (int i = 0; i < 7; ++i) {
    assert(leaf_node.key.buf[i] == -1);
    assert(leaf_node.value_buf8[i] == -1);
    assert(leaf_node.value_buf15[i] == -1);
  }
  assert(leaf_node.value_buf8[7] == 0);
  leaf_node.value_ptr = 0xffffffffffffff;
  for (int i = 8; i < 15; ++i) {
    assert(leaf_node.value_buf15[i] == -1);
  }
  leaf_node.value_ptr = 0x00ffffffffffff00;
  assert(leaf_node.value_buf15[8] == 0);

  static_assert(sizeof(Node4) == 48);
  static_assert(alignof(Node4) >= kMinAlignment);

  // It is Node4's responsibility to free "ptr".
  char *ptr = new char[10];
  Node4 node_4;
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
  node_48.key.ptr = 0xffffffffffffff;
  node_48.key_len = 0;
  for (char i: node_48.key.buf) {
    assert(i == -1);
  }

  static_assert(sizeof(Node256) == 256 * 8 + 8);
  Node256 node_256;
  node_256.key_len = 0;
  node_256.key.ptr = 0xffffffffffffff;
  node_256.key_len = 0;
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
