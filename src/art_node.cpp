// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#include <emmintrin.h>
#include <immintrin.h>

#include "art/art_node.h"
#include "util.h"

namespace ART_NAMESPACE {

size_t KeyBuf::CmpMismatch(const char *buffer, size_t n) {
  n = std::min(static_cast<size_t>(len), n);
  return MemCmpMismatch(GetAddr(), buffer, n);
}

BufOrPtr::BufOrPtr(const char *ptr, uint8_t len) : len(len) {
  if (len <= 7) {
    memcpy(buf, ptr, len);
  } else {
    char *new_ptr = new char[len];
    memcpy(new_ptr, ptr, len);
    this->ptr = reinterpret_cast<uint64_t>(new_ptr);
  }
}

void BufOrPtr::Assign(const char *buffer, size_t n) {
  if (len > 7) {
    delete[]reinterpret_cast<char *>(ptr);
  }
  if (n <= 7) {
    memcpy(buf, buffer, n);
  } else {
    char *new_ptr = new char[n];
    memcpy(new_ptr, buffer, n);
    ptr = reinterpret_cast<uint64_t>(new_ptr);
  }
  len = n;
}

void BufOrPtr::CopyToBuffer(std::string &buffer) const {
  auto addr = GetAddr();
  buffer.assign(addr, len);
}

BufOrPtr NodePtr::ToBufOrPtr() const {
  BufOrPtr res = BufOrPtr();
  res.len = len;
  if (len <= 7) {
    memcpy(res.buf, buf, len);
  } else {
    res.ptr = (uint64_t) GetValuePtr();
  }
  return res;
}

LeafNodeWithPrefixKey::LeafNodeWithPrefixKey(const partial_key_t *prefix_key_buf,
                                             uint8_t prefix_key_len,
                                             const char *value_buf,
                                             uint8_t value_len, BufOrPtr prefix_value) : LeafNodeWithPrefixKey(
    prefix_key_buf,
    prefix_key_len,
    BufOrPtr(value_buf, value_len),
    prefix_value) {}

LeafNodeWithPrefixKey::LeafNodeWithPrefixKey(const partial_key_t *prefix_key_buf,
                                             uint8_t prefix_key_len,
                                             BufOrPtr value, BufOrPtr prefix_value)
    : key(prefix_key_buf, prefix_key_len, true),
      prefix_value(prefix_value),
      value(value) {}

bool LeafNodeWithPrefixKey::GetIfMatch(
    const partial_key_t *key_buffer,
    uint8_t key_len,
    std::string &value_buffer) const {
  bool res;
  if (key_len == 0) {
    res = !prefix_value.IsUndefined();
    if (res) {
      prefix_value.CopyToBuffer(value_buffer);
    }
  } else {
    res = key.IsEqualTo(key_buffer, key_len);
    if (res) {
      value.CopyToBuffer(value_buffer);
    }
  }
  return res;
}

Node4WithPrefixKey *Node4WithPrefixKey::NewInline(const char *prefix_key_buf, uint8_t prefix_key_len, BufOrPtr value) {
  void *ptr = malloc(sizeof(Node4WithPrefixKey) + prefix_key_len);
  auto node = new(ptr)Node4WithPrefixKey(prefix_key_buf, prefix_key_len, value);
  return node;
}

Node4WithPrefixKey::Node4WithPrefixKey(const char *prefix_key_buf,
                                       uint8_t prefix_key_len,
                                       BufOrPtr value)
    : count(0), key(prefix_key_buf, prefix_key_len, true), value(value) {
  assert(prefix_key_len > 0);
}

NodePtr Node16WithPrefixKey::FindChild(partial_key_t key_span) {
  __m128i key_spans = _mm_set1_epi8(key_span);
  __m128i _partial_key = _mm_load_si128(reinterpret_cast<const __m128i *>(&partial_key));
  __m128i result = _mm_cmpeq_epi8(key_spans, _partial_key);
  int mask = (1 << (count - 1)) - 1;
  int idx = _mm_movemask_epi8(result) & mask;
  return idx > 0 ? child_ptrs[_tzcnt_u32(static_cast<uint32_t>(idx))] : NodePtr();
}

NodePtr Node48::FindChild(partial_key_t key_span) {
  uint8_t idx = child_indexes[static_cast<uint8_t>(key_span)];
  return child_ptrs[idx];
}

NodePtr Node256::FindChild(partial_key_t key_span) {
  return child_ptrs[static_cast<uint8_t>(key_span)];
}

NodePtr NodePtr::NewLeafNode(const partial_key_t *prefix_key_buf,
                             uint8_t prefix_key_len,
                             const char *value_buf,
                             uint8_t value_len,
                             BufOrPtr prefix_value) {
  if (prefix_key_len == 0) {
    NodePtr node_ptr;
    node_ptr.ToInlineLeafNode(value_buf, value_len);
    return node_ptr;
  }

  auto *leaf_node_ptr = new LeafNodeWithPrefixKey(prefix_key_buf, prefix_key_len, value_buf, value_len, prefix_value);
  return NodePtr(leaf_node_ptr, NodeType::kLeafNodeWithPrefixKey);
}

NodePtr NodePtr::NewLeafNode(const char *prefix_key_buf,
                             uint8_t prefix_key_len,
                             BufOrPtr value, BufOrPtr prefix_value) {

  if (prefix_key_len == 0) {
    NodePtr node_ptr;
    node_ptr.ToInlineLeafNode(value.GetAddr(), value.len);
    return node_ptr;
  }

  auto *leaf_node_ptr = new LeafNodeWithPrefixKey(prefix_key_buf, prefix_key_len, value, prefix_value);
  return NodePtr(leaf_node_ptr, NodeType::kLeafNodeWithPrefixKey);
}

void NodePtr::GetLeafValue(std::string &buffer) const {
  buffer.assign(len <= 6 ? buf : GetValuePtr(), len);
}

void NodePtr::ToInlineLeafNode(const char *value_buffer, uint8_t value_len) {
  if (len > 6) {
    delete[]GetValuePtr();
  }
  if (value_len <= 6) {
    memcpy(buf, value_buffer, value_len);
  } else {
    char *new_value_ptr = new char[value_len];
    memcpy(new_value_ptr, value_buffer, value_len);
    SetValuePtr(new_value_ptr);
  }
  len = value_len;
  SetNodeType(NodeType::kInlineLeafNode);
}

#ifdef ART_BUILD_TESTS
void NodePtr::TEST_Layout() {
  for (char &c : buf) {
    c = 'h';
  }
  SetNodeType(NodeType::kInlineLeafNode);
  for (char &c : buf) {
    assert(c == 'h');
  }
  bits_ = 123;
  assert(value_ptr == 123);
  value_ptr = 45678;
  assert(bits_ == 45678);
  assert(len == 0);
}

#endif

}