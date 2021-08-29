// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>

#include "art/art_namespace.h"

namespace ART_NAMESPACE {

using partial_key_t = char;

constexpr uint64_t kNodeTypeMask = 0b1111;

struct alignas(8) BufOrPtr {
  BufOrPtr() = default;
  BufOrPtr(const char *ptr, uint8_t len);

  const char *operator+(uint8_t n) const {
    assert(len >= n);
    return len <= 7 ? buf + n : reinterpret_cast<const char *>(ptr + n);
  }

  char operator[](uint8_t n) const {
    assert(n < len);
    return len <= 7 ? buf[n] : *reinterpret_cast<const char *>(ptr + n);
  }

  const char *GetAddr() const {
    return len <= 7 ? buf : reinterpret_cast<const char *> (ptr);
  }

  bool IsEqualTo(const char *buffer, size_t n) const;
  size_t CmpMismatch(const char *buffer, size_t n);
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

// Wrapper of `Node4WithPrefixKey`, `Node16`, `Node48` and `Node256`'s pointer.
// Pointer MUST be aligned with at least 8 bytes (remaining 3 bits for NodeType).
struct NodePtr {

  static NodePtr NewLeafWithPrefixKey(const char *prefix_key_buf,
                                      uint8_t prefix_key_len,
                                      const char *value_buf,
                                      uint8_t value_len, BufOrPtr prefix_value);

  static NodePtr NewLeafWithPrefixKey(const char *prefix_key_buf,
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
        char buf[6];
      };
      uint8_t len;
    };
  };
};

template<class Node>
struct __attribute__((packed)) Node4Base {

  NodePtr FindChild(partial_key_t key_span) {
    for (int i = 0; i < static_cast<Node *>(this)->GetCount(); ++i) {
      if (partial_key[i] == key_span) {
        return NodePtr{child_ptrs[i]};
      }
    }
    return NodePtr();
  }

  NodePtr child_ptrs[4];
  partial_key_t partial_key[4];
};

struct Node4 : public Node4Base<Node4> {
  Node4() : count(0) {}
  Node4(BufOrPtr value) : value(value), count(0) {
  }
  void AddKey(partial_key_t key, NodePtr ptr);

  uint32_t GetCount() const { return count; }

  uint32_t count;
  BufOrPtr value;
};

// lazy expansion: partial key may be stored in leaf node
struct LeafNodeWithPrefixKey {

  BufOrPtr key, prefix_value, value;

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
};

class Node4WithPrefixKey : public Node4Base<Node4WithPrefixKey> {
 public:

  Node4WithPrefixKey(const char *prefix_key_buf, uint8_t prefix_key_len, BufOrPtr value = BufOrPtr());
  ~Node4WithPrefixKey();

  void AddKey(partial_key_t key, NodePtr ptr);
  inline void IncCount() {
    assert(GetCount() < 4);
    ++__prefix_key_ptr_value_count;
  }

  inline void DecCount() {
    assert(GetCount() > 0);
    --__prefix_key_ptr_value_count;
  }

  inline uint32_t GetCount() const {
    return __prefix_key_ptr_value_count & 0b111;
  }

  inline char *GetPrefixKeyPtr() const {
    return reinterpret_cast<char *>(__prefix_key_ptr_value_count & (UINT64_MAX ^ 0b111));
  }

  inline void SetPrefixKeyPtr(const char *prefix_key_ptr) {
    auto n = reinterpret_cast<uint64_t>(prefix_key_ptr);

    assert((n & 0xff00000000000007) == 0);
    __prefix_key_ptr_value_count = n | GetCount();
  }

  uint8_t prefix_key_len;
 private:
  union {
    char prefix_key_buf10[10];
    struct __attribute__((packed)) {
      char prefix_key_buf4[4];
      uint64_t __prefix_key_ptr_value_count: 56;
    };
  };
 public:
  BufOrPtr prefix_value, value;
};

struct Node16 {
  // SSE2 comparison
  alignas(16) partial_key_t partial_key[16];
  NodePtr child_ptrs[16]{NodePtr()};
  BufOrPtr value;
  union __attribute__((packed)) {
    struct {
      uint8_t len;
      partial_key_t buf6[6];
    };
    uint64_t ptr: 56;
  } prefix_key;
  uint8_t key_is_ptr: 1;
  uint8_t count: 7;

  NodePtr FindChild(partial_key_t key_span);
};

struct Node48 {
  uint8_t child_indexes[256];
  NodePtr child_ptrs[48]{NodePtr()};
  uint64_t bitmap;
  BufOrPtr key;
  BufOrPtr value;

  NodePtr FindChild(partial_key_t key_span);
};

struct Node256 {
  NodePtr child_ptrs[256]{NodePtr()};

  BufOrPtr key;
  BufOrPtr value;

  NodePtr FindChild(partial_key_t key_span);
};

}
