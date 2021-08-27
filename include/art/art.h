// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#pragma once
#include <cstddef>
#include <string>
#include <cassert>

#include "art/art_namespace.h"

namespace ART_NAMESPACE {

constexpr uint64_t kNodeTypeMask = 0b111;
constexpr size_t kMinAlignment = kNodeTypeMask + 1;
constexpr size_t kCacheLineSize = 64;

using partial_key_t = char;

class AdaptiveRadixTree {
 private:
  enum class NodeType {
    kLeafNode = 0,
    kNode4 = 1,
    kNode16 = 2,
    kNode48 = 3,
    kNode256 = 4,
  };

  struct alignas(8) LeafNode;
  struct alignas(8) Node4;
  struct Node16;
  struct Node48;
  struct Node256;

  // Wrapper of `Node4`, `Node16`, `Node48` and `Node256`'s pointer.
  // Pointer MUST be aligned with at least 8 bytes (remaining 3 bits for NodeType).
  struct NodePtr {

    static NodePtr NewLeaf(const char *value_buf, uint8_t value_len);
    static NodePtr NewLeaf(const char *prefix_key_buf,
                           uint8_t prefix_key_len,
                           const char *value_buf,
                           uint8_t value_len);

    NodePtr() : bits_(0) {}

    NodePtr(void *ptr, NodeType tp) : bits_(
        reinterpret_cast<uint64_t>(ptr) | static_cast<uint64_t>(tp)) {
      assert((reinterpret_cast<uint64_t>(ptr) & kNodeTypeMask) == 0);
    }

    inline void *GetPtr() const {
      return reinterpret_cast<void *>(bits_ & (UINT64_MAX - kNodeTypeMask));
    }

    inline LeafNode *ToLeafNode() const {
      assert(GetNodeType() == NodeType::kLeafNode);
      return reinterpret_cast<LeafNode *>(bits_);
    }

    inline NodeType GetNodeType() const {
      return static_cast<NodeType>(bits_ & kNodeTypeMask);
    }

    inline void SetPtr(void *ptr) {
      auto n = reinterpret_cast<uint64_t>(ptr);
      assert((n & kNodeTypeMask) == 0);
      bits_ = n | (bits_ & kNodeTypeMask);
    }

    inline void SetNodeType(NodeType tp) {
      bits_ = (bits_ & (UINT64_MAX - kNodeTypeMask)) | static_cast<uint64_t>(tp);
    }

    inline bool IsNullptr() const { return bits_ == 0; }

   private:
    uint64_t bits_;
  };

 public:
  AdaptiveRadixTree();
  ~AdaptiveRadixTree();

  bool Insert(const partial_key_t *key_buffer, uint8_t key_len, const char *value_buffer, uint8_t value_len);
  bool Get(const partial_key_t *key_buffer, uint8_t key_len, std::string &value_buffer) const;
  bool Delete(const partial_key_t *key_buffer, size_t key_len);

  inline size_t GetSize() const { return size_; }

#ifdef ART_BUILD_TESTS
  static void TEST_Layout();
#endif

 private:
  NodePtr root_;
  size_t size_;
};

union __attribute__((packed)) BufOrPtr7Bytes {
  char buf[7];
  uint64_t ptr: 56;
};

// lazy expansion: partial key may be stored in leaf node
struct alignas(8) AdaptiveRadixTree::LeafNode {

  // header
  uint8_t no_partial_key: 1;
  uint8_t value_len: 7;

  union __attribute__((packed)) {

    // has partial key
    struct __attribute__((packed)) {
      BufOrPtr7Bytes key;
      uint8_t partial_key_len;
      BufOrPtr7Bytes value7;
    };

    // no partial key
    struct {
      union {
        char value_buf15[15];
        struct __attribute__((packed)) {
          char value_buf8[8];
          uint64_t value_ptr: 56;
        };
      };
    };
  };

  // Return true if there already exists partial_key.
  bool Insert(const partial_key_t *partial_key_buffer,
              uint8_t partial_key_len,
              const char *value_buffer,
              uint8_t value_len);

  bool GetIfMatch(uint8_t key_compared,
                  const partial_key_t *key_buffer,
                  uint8_t key_len,
                  std::string &value_buffer) const;
 private:
  inline bool IsInlineKey() const {
    return partial_key_len <= 7;
  }

  void UpdateNoPartialKey(const char *value_buffer,
                          uint8_t value_len);
  void UpdateHasPartialKey(const char *value_buffer,
                           uint8_t value_len);

  void GetNoPartialKey(std::string &value_buffer) const;
  inline void GetHasPartialKey(std::string &value_buffer) const;
};

struct alignas(8)  AdaptiveRadixTree::Node4 {
  NodePtr child_ptrs[4]{NodePtr()};
  partial_key_t partial_key[4];

  struct {
    uint8_t prefix_key_len;
    union {
      char prefix_key_buf10[10];
      struct __attribute__((packed)) {
        char prefix_key_buf4[4];
        uint64_t __prefix_key_ptr_count: 56;
      };
    };
  };

  inline void IncCount() {
    assert(GetCount() < 4);
    ++__prefix_key_ptr_count;
  }

  inline void DecCount() {
    assert(GetCount() > 0);
    --__prefix_key_ptr_count;
  }

  inline uint8_t GetCount() const {
    return __prefix_key_ptr_count & 0b111;
  }

  inline char *GetPrefixKeyPtr() const {
    return reinterpret_cast<char *>(__prefix_key_ptr_count & (UINT64_MAX ^ 0b111));
  }

  inline void SetPrefixKeyPtr(const char *prefix_key_ptr) {
    auto n = reinterpret_cast<uint64_t>(prefix_key_ptr);

    assert((n & 0xff00000000000007) == 0);
    __prefix_key_ptr_count = n | GetCount();
  }

  NodePtr FindChild(partial_key_t key_span);
};

struct AdaptiveRadixTree::Node16 {
  // SSE2 comparison
  alignas(16) partial_key_t partial_key[16];
  NodePtr child_ptrs[16]{NodePtr()};
  struct {
    uint8_t len;

    union __attribute__((packed)) {
      struct __attribute__((packed)) {
        partial_key_t buf7[7];
        uint64_t ptr: 56;
      };
      partial_key_t buf14[14];
    };
  } prefix_key;
  uint8_t count;

  NodePtr FindChild(partial_key_t key_span);
};

struct AdaptiveRadixTree::Node48 {
  uint8_t child_indexes[256];
  NodePtr child_ptrs[48]{NodePtr()};
  uint64_t bitmap;
  struct {
    uint8_t key_len;
    BufOrPtr7Bytes key;
  };

  NodePtr FindChild(partial_key_t key_span);
};

struct AdaptiveRadixTree::Node256 {
  NodePtr child_ptrs[256]{NodePtr()};

  struct {
    uint8_t key_len;
    BufOrPtr7Bytes key;
  };

  NodePtr FindChild(partial_key_t key_span);
};

}