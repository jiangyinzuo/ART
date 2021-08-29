// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#include <cassert>
#include <cstring>
#include <emmintrin.h>
#include <immintrin.h>

#include "art/art_node.h"
#include "util.h"

namespace ART_NAMESPACE {

BufOrPtr::BufOrPtr(const char *ptr, uint8_t len) : len(len) {
  if (len <= 7) {
    memcpy(buf, ptr, len);
  } else {
    char *new_ptr = new char[len];
    memcpy(new_ptr, ptr, len);
    this->ptr = reinterpret_cast<uint64_t>(new_ptr);
  }
}

bool BufOrPtr::IsEqualTo(const char *buffer, size_t n) const {
  return n == len && memcmp(len <= 7 ? buf : reinterpret_cast<char *>(ptr), buffer, n) == 0;
}

size_t BufOrPtr::CmpMismatch(const char *buffer, size_t n) {
  n = std::min(static_cast<size_t>(len), n);
  return MemCmpMismatch(len <= 7 ? buf : reinterpret_cast<char *>(ptr), buffer, n);
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

LeafNodeWithPrefixKey::LeafNodeWithPrefixKey(const partial_key_t *prefix_key_buf,
                                             uint8_t prefix_key_len,
                                             const char *value_buf,
                                             uint8_t value_len, BufOrPtr prefix_value) : key(prefix_key_buf,
                                                                                             prefix_key_len),
                                                                                         prefix_value(prefix_value),
                                                                                         value(value_buf, value_len) {}

LeafNodeWithPrefixKey::LeafNodeWithPrefixKey(const partial_key_t *prefix_key_buf,
                                             uint8_t prefix_key_len,
                                             BufOrPtr value, BufOrPtr prefix_value)
    : key(prefix_key_buf, prefix_key_len),
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

Node4WithPrefixKey::Node4WithPrefixKey(const char *prefix_key_buf,
                                       uint8_t prefix_key_len,
                                       BufOrPtr value)
    : __prefix_key_ptr_value_count(0), prefix_key_len(prefix_key_len), value(value) {
  assert(prefix_key_len > 0);
  if (prefix_key_len <= 10) {
    memcpy(prefix_key_buf10, prefix_key_buf, prefix_key_len);
  } else {
    memcpy(prefix_key_buf4, prefix_key_buf, 4);
    char *ptr = new char[prefix_key_len - 4];
    SetPrefixKeyPtr(ptr);
  }
}

Node4WithPrefixKey::~Node4WithPrefixKey() {
  if (prefix_key_len > 10) {
    delete[] GetPrefixKeyPtr();
  }
}

void Node4WithPrefixKey::AddKey(partial_key_t key, NodePtr ptr) {
  auto idx = GetCount();
  partial_key[idx] = key;
  child_ptrs[idx] = ptr;
  IncCount();
}

NodePtr Node16::FindChild(partial_key_t key_span) {
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

NodePtr NodePtr::NewLeafWithPrefixKey(const partial_key_t *prefix_key_buf,
                                      uint8_t prefix_key_len,
                                      const char *value_buf,
                                      uint8_t value_len,
                                      BufOrPtr prefix_value) {
  assert(prefix_key_len > 0);
  auto *leaf_node_ptr = new LeafNodeWithPrefixKey(prefix_key_buf, prefix_key_len, value_buf, value_len, prefix_value);
  return NodePtr(leaf_node_ptr, NodeType::kLeafNodeWithPrefixKey);
}

NodePtr NodePtr::NewLeafWithPrefixKey(const char *prefix_key_buf,
                                      uint8_t prefix_key_len,
                                      BufOrPtr value, BufOrPtr prefix_value) {
  assert(prefix_key_len > 0);
  auto *leaf_node_ptr = new LeafNodeWithPrefixKey(prefix_key_buf, prefix_key_len, value, prefix_value);
  return NodePtr(leaf_node_ptr, NodeType::kInlineLeafNode);
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
  bits_ = 123;
  assert(value_ptr == 123);
  value_ptr = 45678;
  assert(bits_ == 45678);
  assert(len == 0);
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

#endif

void Node4::AddKey(partial_key_t key, NodePtr ptr) {

}

}