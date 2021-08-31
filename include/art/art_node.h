// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <cstring>

#include "art/art_namespace.h"

namespace ART_NAMESPACE {

using partial_key_t = char;

struct __attribute__((packed)) ValueBufOrPtr {
  ValueBufOrPtr() : len(0), ptr(0) {}
  ValueBufOrPtr(const char *ptr, uint8_t len);

  const char *GetAddr() const {
    return len <= 7 ? buf : reinterpret_cast<const char *> (ptr);
  }

  bool Update(const char *value_buffer, uint8_t value_len) {
    bool res = !IsUndefined();
    Assign(value_buffer, value_len);
    return res;
  }

  void Assign(const char *buffer, size_t n);

  // Return true if old value is defined.
  bool CopyToBuffer(std::string &buffer) const;

  bool IsUndefined() const {
    return len == 0 && buf[6] == 0;
  }

  bool IsEmpty() const {
    return len == 0 && buf[6] == 1;
  }

  void MayFree() {
    if (len > 7) {
      delete[]reinterpret_cast<char *>(ptr);
    }
  }

  uint8_t len;
  union __attribute__((packed)) {
    char buf[7];
    uint64_t ptr: 56;
  };
};

class __attribute__((packed)) PrefixKeyValueBuf {
 public:
  PrefixKeyValueBuf() = default;
  PrefixKeyValueBuf(const PrefixKeyValueBuf &) = delete;
  PrefixKeyValueBuf(const char *prefix_key_buf, uint8_t prefix_key_len) {
    data_[0] = prefix_key_len;
    memcpy(data_ + 9, prefix_key_buf, prefix_key_len);
    *(uint64_t *)(data_ + 1) = 0;
  }

  PrefixKeyValueBuf(const char *prefix_key_buf, uint8_t prefix_key_len, ValueBufOrPtr prefix_value) {
    data_[0] = prefix_key_len;
    *reinterpret_cast<ValueBufOrPtr *>(data_ + 1) = prefix_value;
    memcpy(data_ + 9, prefix_key_buf, prefix_key_len);
  }

  void *operator new(size_t) = delete;

  bool MatchPrefixKey(const partial_key_t *&key_buffer, uint8_t &key_len);

  size_t KeyCmpMismatch(const char *buffer, size_t n);

  bool KeyIsEqualTo(const char *buffer, size_t n) const {
    return n == GetKeyLen() && memcmp(GetKeyBuf(), buffer, n) == 0;
  }

  void KeyMoveBackward(uint8_t n) {
    assert(GetKeyLen() >= n);
    memcpy(GetKeyBuf(), GetKeyBuf() + n, n);
    data_[0] -= n;
  }

  uint8_t GetKeyLen() const {
    return data_[0];
  }

  ValueBufOrPtr *GetValueBufOrPtr() const {
    return reinterpret_cast<ValueBufOrPtr *>(const_cast<uint8_t *>(data_ + 1));
  }

  char *GetKeyBuf() const {
    return (char *) (data_ + 9);
  }

 private:
  uint8_t data_[0];
};

constexpr uint64_t kNodeTypeMask = 0b111;
constexpr uint64_t kHasPrefixKeyMask = 0b1000;
constexpr uint64_t kPtrMask = UINT64_MAX ^ kNodeTypeMask ^ kHasPrefixKeyMask;

enum class NodeType {
  kNullPtr = 0,
  // leaf node can be regarded as "Node1", inline leaf node only contains value.
  kInlineLeafNode = 1,
  kLeafNodeWithPrefixKey = 2,
  kNode4 = 3,
  kNode16 = 4,
  kNode48 = 5,
  kNode256 = 6,
};

// Wrapper of `Node4WithPrefixKey`, `Node16WithPrefixKey`, `Node48` and `Node256`'s pointer.
// Pointer MUST be aligned with at least 8 bytes (remaining 3 bits for NodeType).
struct NodePtr {

  static NodePtr NewLeafNode(const char *prefix_key_buf,
                             uint8_t prefix_key_len,
                             const char *value_buf,
                             uint8_t value_len, ValueBufOrPtr prefix_value);

  static NodePtr NewLeafNode(const char *prefix_key_buf,
                             uint8_t prefix_key_len, ValueBufOrPtr value, ValueBufOrPtr prefix_value);

  NodePtr() : bits_(0) {}

  NodePtr(void *ptr, NodeType tp, bool has_prefix_key) : bits_(
      reinterpret_cast<uint64_t>(ptr) | has_prefix_key << 3 | static_cast<uint64_t>(tp)) {
    assert((reinterpret_cast<uint64_t>(ptr) & ~kPtrMask) == 0);
  }

  void GetLeafValue(std::string &buffer) const;
  void ToInlineLeafNode(const char *value_buffer,
                        uint8_t value_len);

  template<class T>
  inline T *GetPtr() const {
    return reinterpret_cast<T *>(bits_ & kPtrMask);
  }

  ValueBufOrPtr ToBufOrPtr() const;

  const char *GetValuePtr() const {
    return reinterpret_cast<char *>(value_ptr & kPtrMask);
  }

  bool HasPrefixKey() const {
    return (bits_ & kHasPrefixKeyMask) > 0;
  }

  NodeType GetNodeType() const {
    return static_cast<NodeType>(bits_ & kNodeTypeMask);
  }

  void SetPtr(void *ptr) {
    auto n = reinterpret_cast<uint64_t>(ptr);
    assert((n & ~kPtrMask) == 0);
    bits_ = n | (bits_ & ~kPtrMask);
  }

  void SetValuePtr(const char *value_ptr) {
    auto n = reinterpret_cast<uint64_t>(value_ptr);
    assert((n & ~kPtrMask) == 0);
    this->value_ptr = n | (this->value_ptr & ~kPtrMask);
  }

  void SetNoPrefixKey() {
    bits_ &= ~kHasPrefixKeyMask;
  }

  void SetNodeType(NodeType tp) {
    bits_ = (bits_ & ~kNodeTypeMask) | static_cast<uint64_t>(tp);
  }

  bool IsNullptr() const { return bits_ == 0; }

#ifdef ART_BUILD_TESTS
  void TEST_Layout();
#endif

 private:
  union {
    uint64_t bits_;
    struct {
      union __attribute__((packed)) {
        uint64_t value_ptr: 56;
        struct {
          char __invalid;
          char buf[6];
        };
      };
      uint8_t len;
    };
  };
};

// lazy expansion: partial pre_kv may be stored in leaf node
class LeafNodeWithPrefixKey {
 public:
  void *operator new(size_t) = delete;
  void operator delete(void *) = delete;

  static LeafNodeWithPrefixKey *New(const char *prefix_key_buf,
                                    uint8_t prefix_key_len,
                                    ValueBufOrPtr value,
                                    ValueBufOrPtr prefix_value);

  bool GetIfMatch(
      const partial_key_t *key_buffer,
      uint8_t key_len,
      std::string &value_buffer) const;

  NodePtr ToChildNode(uint8_t mismatch_idx);

  ValueBufOrPtr node_value;
  PrefixKeyValueBuf pre_kv;

 private:
  LeafNodeWithPrefixKey(const partial_key_t *prefix_key_buf,
                        uint8_t prefix_key_len, ValueBufOrPtr node_value, ValueBufOrPtr prefix_value);
  void *operator new(size_t, void *ptr) {
    return ptr;
  }
};

static_assert(sizeof(LeafNodeWithPrefixKey) == 8);

class Node4 {
 public:

  static Node4 *New(ValueBufOrPtr node_value);
  static Node4 *NewWithPrefixKey(const char *prefix_key_buf,
                                 uint8_t prefix_key_len,
                                 ValueBufOrPtr value = ValueBufOrPtr());

  void *operator new(size_t) = delete;
  void operator delete(void *) = delete;

  NodePtr FindChild(partial_key_t key_span);

  // Return true if child node is successfully added.
  bool TryAppendChild(partial_key_t key, NodePtr ptr);
  NodePtr ToChildNode(uint8_t n);
  inline uint32_t GetCount() const { return count; }

  NodePtr child_ptrs[4];
  ValueBufOrPtr node_value;
  partial_key_t partial_key[4];
  uint8_t count;
  PrefixKeyValueBuf pre_kv;

 private:
  Node4(ValueBufOrPtr node_value) : node_value(node_value), count(0) {}
  Node4(const char *prefix_key_buf,
        uint8_t prefix_key_len,
        ValueBufOrPtr value);

  void *operator new(size_t, void *ptr) { return ptr; }
};

struct __attribute__((packed)) Node16 {
  void *operator new(size_t) = delete;
  void operator delete(void *) = delete;

  NodePtr FindChild(partial_key_t key_span);

  // SSE2 comparison
  alignas(16) partial_key_t partial_key[16];
  NodePtr child_ptrs[16];
  ValueBufOrPtr node_value;
  uint8_t count;
  PrefixKeyValueBuf pre_kv;
};

static_assert(sizeof(Node16) == 16 + 16 * 8 + 16);

struct Node48 {
  void *operator new(size_t) = delete;
  void operator delete(void *) = delete;

  uint8_t child_indexes[256];
  NodePtr child_ptrs[48];
  uint64_t bitmap;
  ValueBufOrPtr node_value;
  PrefixKeyValueBuf pre_kv;

  NodePtr FindChild(partial_key_t key_span);
};

struct Node256 {
  void *operator new(size_t) = delete;
  void operator delete(void *) = delete;

  NodePtr child_ptrs[256]{NodePtr()};
  ValueBufOrPtr node_value;
  PrefixKeyValueBuf pre_kv;

  NodePtr FindChild(partial_key_t key_span);
};

}
