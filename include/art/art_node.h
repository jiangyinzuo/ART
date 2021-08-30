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

struct __attribute__((packed)) KeyBuf {
  KeyBuf(const char *prefix_key_buf, uint8_t prefix_key_len, bool is_offset)
      : len(prefix_key_len), is_offset(is_offset) {
    if (is_offset) {
      offset = 0;
      memcpy((void *) GetAddr(), prefix_key_buf, prefix_key_len);
    } else {
      SetPtr(prefix_key_buf);
    }
  }

  const char *operator+(uint8_t n) const {
    return GetAddr() + n;
  }

  char operator[](uint8_t n) const {
    assert(n < len);
    return GetAddr()[n];
  }
  size_t CmpMismatch(const char *buffer, size_t n);

  bool IsEqualTo(const char *buffer, size_t n) const {
    return n == len && memcmp(GetAddr(), buffer, n) == 0;
  }

  const char *GetAddr() const {
    return is_offset ? is_offset_data + offset : reinterpret_cast<const char *>(ptr[0] & 0xffffffffffffff00);
  }
  void SetPtr(const char *prefix_key_buf) {
    assert(!is_offset);
    ptr[0] = ptr[0] & 0x00000000000000ff | (reinterpret_cast<uint64_t>(prefix_key_buf) & 0xffffffffffffff00);
  }

 private:
  uint64_t ptr[0];
 public:
  uint8_t len: 7;
  uint8_t is_offset: 1;
 private:
  uint8_t offset;
  char is_offset_data[0];
};

struct alignas(8) BufOrPtr {
  BufOrPtr() = default;
  BufOrPtr(const char *ptr, uint8_t len);

  const char *GetAddr() const {
    return len <= 7 ? buf : reinterpret_cast<const char *> (ptr);
  }

  void Assign(const char *buffer, size_t n);
  void CopyToBuffer(std::string &buffer) const;

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

constexpr uint64_t kNodeTypeMask = 0b1111;

enum class NodeType {
  kNullPtr = 0,
  // leaf node can be regarded as "Node1", inline leaf node only contains value.
  kInlineLeafNode = 1,
  kNode4 = 2,
  kNode16 = 3,
  kNode48 = 4,
  kNode256 = 5,
  kLeafNodeWithPrefixKey = 6,
  kNode4WithPrefixKey = 7,
  kNode16WithPrefixKey = 8,
  kNode48WithPrefixKey = 9,
  kNode256WithPrefixKey = 10,
};

// Wrapper of `Node4WithPrefixKey`, `Node16WithPrefixKey`, `Node48` and `Node256`'s pointer.
// Pointer MUST be aligned with at least 8 bytes (remaining 3 bits for NodeType).
struct NodePtr {

  static NodePtr NewLeafNode(const char *prefix_key_buf,
                             uint8_t prefix_key_len,
                             const char *value_buf,
                             uint8_t value_len, BufOrPtr prefix_value);

  static NodePtr NewLeafNode(const char *prefix_key_buf,
                             uint8_t prefix_key_len, BufOrPtr value, BufOrPtr prefix_value);

  NodePtr() : bits_(0) {}

  NodePtr(void *ptr, NodeType tp) : bits_(
      reinterpret_cast<uint64_t>(ptr) | static_cast<uint64_t>(tp)) {
    assert((reinterpret_cast<uint64_t>(ptr) & kNodeTypeMask) == 0);
  }

  void GetLeafValue(std::string &buffer) const;
  void ToInlineLeafNode(const char *value_buffer,
                        uint8_t value_len);

  template<class T>
  inline T *GetPtr() const {
    return reinterpret_cast<T *>(bits_ & (UINT64_MAX - kNodeTypeMask));
  }

  BufOrPtr ToBufOrPtr() const;

  inline const char *GetValuePtr() const {
    return reinterpret_cast<char *>(value_ptr & (UINT64_MAX - kNodeTypeMask));
  }

  inline NodeType GetNodeType() const {
    return static_cast<NodeType>(bits_ & kNodeTypeMask);
  }

  inline void SetPtr(void *ptr) {
    auto n = reinterpret_cast<uint64_t>(ptr);
    assert((n & kNodeTypeMask) == 0);
    bits_ = n | (bits_ & kNodeTypeMask);
  }

  inline void SetValuePtr(const char *value_ptr) {
    auto n = reinterpret_cast<uint64_t>(value_ptr);
    assert((n & kNodeTypeMask) == 0);
    this->value_ptr = n | (this->value_ptr & kNodeTypeMask);
  }

  inline void SetNodeType(NodeType tp) {
    bits_ = (bits_ & (UINT64_MAX - kNodeTypeMask)) | static_cast<uint64_t>(tp);
  }

  inline bool IsNullptr() const { return bits_ == 0; }

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

struct Node4 {
  Node4() : count(0) {}
  Node4(BufOrPtr node_value) : node_value(node_value), count(0) {
  }

  inline uint32_t GetCount() const { return count; }

  inline void IncCount() { ++count; }

  NodePtr child_ptrs[4];
  BufOrPtr node_value;
  partial_key_t partial_key[4];
  uint8_t count;
};

// lazy expansion: partial key may be stored in leaf node
struct LeafNodeWithPrefixKey {

  LeafNodeWithPrefixKey(const partial_key_t *prefix_key_buf,
                        uint8_t prefix_key_len,
                        const char *value_buf,
                        uint8_t value_len, BufOrPtr prefix_value);

  LeafNodeWithPrefixKey(const partial_key_t *prefix_key_buf,
                        uint8_t prefix_key_len, BufOrPtr value, BufOrPtr prefix_value);

  bool GetIfMatch(
      const partial_key_t *key_buffer,
      uint8_t key_len,
      std::string &value_buffer) const;

  BufOrPtr prefix_value, value;
  KeyBuf key;
};

class Node4WithPrefixKey {
 public:
  static Node4WithPrefixKey *NewInline(const char *prefix_key_buf, uint8_t prefix_key_len, BufOrPtr value = BufOrPtr());

  uint32_t GetCount() const { return count; }

  NodePtr child_ptrs[4];
  BufOrPtr prefix_value, value;
  partial_key_t partial_key[4];
  uint8_t count;
  KeyBuf key;
 private:
  Node4WithPrefixKey(const char *prefix_key_buf,
                     uint8_t prefix_key_len,
                     BufOrPtr value);
};

template<class T>
concept Node4Concept = requires(T t) {
  { t.GetCount() } -> std::same_as<uint32_t>;
  t.count;
};

template<Node4Concept Node4>
NodePtr Node4FindChild(Node4 *node4, partial_key_t key_span) {
  for (uint32_t i = 0; i < node4->GetCount(); ++i) {
    if (node4->partial_key[i] == key_span) {
      return NodePtr{node4->child_ptrs[i]};
    }
  }
  return NodePtr();
}

// Return true if leaf node is successfully added.
template<Node4Concept N>
bool Node4TryAddLeafNode(N *node4, partial_key_t key, NodePtr ptr) {
  auto idx = node4->GetCount();
  bool res = idx < 4;
  if (res) {
    node4->partial_key[idx] = key;
    node4->child_ptrs[idx] = ptr;
    ++node4->count;
  }
  return res;
}

struct __attribute__((packed)) Node16 {
  // SSE2 comparison
  alignas(16) partial_key_t partial_key[16];
  NodePtr child_ptrs[16];
  BufOrPtr value;
  uint8_t count;
};

static_assert(sizeof(Node16) == 16 + 16 * 8 + 16);

struct __attribute__((packed)) Node16WithPrefixKey {
  // SSE2 comparison
  alignas(16) partial_key_t partial_key[16];
  NodePtr child_ptrs[16];
  BufOrPtr prefix_value, value;
  uint8_t count;
  KeyBuf key;

  NodePtr FindChild(partial_key_t key_span);
};

struct Node48 {
  uint8_t child_indexes[256];
  NodePtr child_ptrs[48];
  uint64_t bitmap;
  BufOrPtr value;

  NodePtr FindChild(partial_key_t key_span);
};

struct Node48WithPrefixKey : public Node48 {
  BufOrPtr prefix_value;
  KeyBuf key;
};

struct Node256 {
  NodePtr child_ptrs[256]{NodePtr()};
  BufOrPtr value;

  NodePtr FindChild(partial_key_t key_span);
};

struct Node256WithPrefixKey : public Node256 {
  BufOrPtr prefix_value;
  KeyBuf key;
};

}
