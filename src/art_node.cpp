// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#include <emmintrin.h>
#include <immintrin.h>

#include <art/art_node.h>
#include "art_node_inner.h"
#include "util.h"

namespace ART_NAMESPACE {

size_t PrefixKeyValueBuf::KeyCmpMismatch(const char *buffer, size_t n) {
  n = std::min(static_cast<size_t>(GetKeyLen()), n);
  return MemCmpMismatch(GetKeyBuf(), buffer, n);
}

bool PrefixKeyValueBuf::MatchPrefixKey(const partial_key_t *&key_buffer, uint8_t &key_len) {
  size_t mismatch_idx = KeyCmpMismatch(key_buffer, key_len);
  key_buffer += mismatch_idx;
  key_len -= mismatch_idx;
  return mismatch_idx == GetKeyLen() && key_len == 0;
}

ValueBufOrPtr::ValueBufOrPtr(const char *ptr, uint8_t len) : len(len) {
  if (len <= 7) {
    memcpy(buf, ptr, len);
  } else {
    char *new_ptr = new char[len];
    memcpy(new_ptr, ptr, len);
    this->ptr = reinterpret_cast<uint64_t>(new_ptr);
  }
}

void ValueBufOrPtr::Assign(const char *buffer, size_t n) {
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

bool ValueBufOrPtr::CopyToBuffer(std::string &buffer) const {
  bool res = !IsUndefined();
  auto addr = GetAddr();
  buffer.assign(addr, len);
  return res;
}

NodePtr NodePtr::NewLeafNode(const partial_key_t *prefix_key_buf,
                             uint8_t prefix_key_len,
                             const char *value_buf,
                             uint8_t value_len,
                             ValueBufOrPtr prefix_value) {
  return NewLeafNode(prefix_key_buf, prefix_key_len, ValueBufOrPtr(value_buf, value_len), prefix_value);
}

NodePtr NodePtr::NewLeafNode(const char *prefix_key_buf,
                             uint8_t prefix_key_len,
                             ValueBufOrPtr value, ValueBufOrPtr prefix_value) {

  if (prefix_key_len == 0) {
    NodePtr node_ptr;
    node_ptr.ToInlineLeafNode(value.GetAddr(), value.len);
    return node_ptr;
  }
  auto *leaf_node_ptr = LeafNodeWithPrefixKey::New(prefix_key_buf, prefix_key_len, value, prefix_value);
  return NodePtr(leaf_node_ptr, NodeType::kLeafNodeWithPrefixKey, true);
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
  SetNoPrefixKey();
}

#ifdef ART_BUILD_TESTS
void NodePtr::TEST_Layout() {
  for (char &c: buf) {
    c = 'h';
  }
  SetNodeType(NodeType::kInlineLeafNode);
  for (char &c: buf) {
    assert(c == 'h');
  }
  bits_ = 123;
  assert(value_ptr == 123);
  value_ptr = 45678;
  assert(bits_ == 45678);
  assert(len == 0);
}

#endif

ValueBufOrPtr NodePtr::ToBufOrPtr() const {
  ValueBufOrPtr res = ValueBufOrPtr();
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
                                             ValueBufOrPtr node_value, ValueBufOrPtr prefix_value)
    : pre_kv(prefix_key_buf, prefix_key_len, prefix_value),
      node_value(node_value) {}

bool LeafNodeWithPrefixKey::GetIfMatch(
    const partial_key_t *key_buffer,
    uint8_t key_len,
    std::string &value_buffer) const {
  bool res;
  if (key_len == 0) {
    res = pre_kv.GetValueBufOrPtr()->CopyToBuffer(value_buffer);
  } else {
    res = pre_kv.KeyIsEqualTo(key_buffer, key_len);
    if (res) {
      node_value.CopyToBuffer(value_buffer);
    }
  }
  return res;
}

NodePtr LeafNodeWithPrefixKey::ToChildNode(uint8_t mismatch_idx) {
  if (mismatch_idx + 1 == pre_kv.GetKeyLen()) {
    // become inline leaf node
    NodePtr node_ptr;
    node_ptr.ToInlineLeafNode(node_value.GetAddr(), node_value.len);
    NodeFree(this);
    return node_ptr;
  }
  pre_kv.KeyMoveBackward(mismatch_idx + 1);
  return NodePtr(this, NodeType::kLeafNodeWithPrefixKey, true);
}

LeafNodeWithPrefixKey *LeafNodeWithPrefixKey::New(const char *prefix_key_buf,
                                                  uint8_t prefix_key_len,
                                                  ValueBufOrPtr value,
                                                  ValueBufOrPtr prefix_value) {

  void *ptr = malloc(sizeof(LeafNodeWithPrefixKey) + prefix_key_len + 1);
  return new(ptr) LeafNodeWithPrefixKey(prefix_key_buf, prefix_key_len, value, prefix_value);
}

Node4 *Node4::New(ValueBufOrPtr node_value) {
  void *ptr = malloc(sizeof(Node4));
  return new(ptr) Node4(node_value);
}

Node4 *Node4::NewWithPrefixKey(const char *prefix_key_buf, uint8_t prefix_key_len, ValueBufOrPtr value) {
  void *ptr = malloc(sizeof(Node4) + prefix_key_len + 1);
  return new(ptr) Node4(prefix_key_buf, prefix_key_len, value);
}

Node4::Node4(const char *prefix_key_buf,
             uint8_t prefix_key_len,
             ValueBufOrPtr value)
    : count(0), pre_kv(prefix_key_buf, prefix_key_len), node_value(value) {
  assert(prefix_key_len > 0);
}

NodePtr Node4::FindChild(partial_key_t key_span) {
  for (uint32_t i = 0; i < GetCount(); ++i) {
    if (partial_key[i] == key_span) {
      return NodePtr{child_ptrs[i]};
    }
  }
  return NodePtr();
}

bool Node4::TryAppendChild(partial_key_t key, NodePtr ptr) {
  auto idx = GetCount();
  bool res = idx < 4;
  if (res) {
    partial_key[idx] = key;
    child_ptrs[idx] = ptr;
    ++count;
  }
  return res;
}

NodePtr Node4::ToChildNode(uint8_t n) {
  // TODO
  return NodePtr();
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

}