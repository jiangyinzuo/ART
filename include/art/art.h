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

  struct Node4;

  struct alignas(kCacheLineSize) Node16;
  struct Node48;
  struct Node256;

  // Wrapper of `Node4`, `Node16`, `Node48` and `Node256`'s pointer.
  // Pointer MUST be aligned with at least 8 bytes (remaining 3 bits for NodeType).
  struct NodePtr {

    NodePtr() : bits_(0) {}

    NodePtr(void *ptr, NodeType tp) : bits_(
        reinterpret_cast<uint64_t>(ptr) | static_cast<uint64_t>(tp)) {
      assert((reinterpret_cast<uint64_t>(ptr) & kNodeTypeMask) == 0);
    }

    inline void *GetPtr() const {
      return reinterpret_cast<void *>(bits_ & (UINT64_MAX - kNodeTypeMask));
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

    bool LeafMatch(uint8_t cur_key_depth, const partial_key_t *key_buffer, uint8_t key_len, std::string &value_buffer);

   private:
    uint64_t bits_;
  };

 public:
  AdaptiveRadixTree();

  bool Insert(const partial_key_t *key_buffer, uint8_t key_len, const char *value_buffer, size_t value_len);
  bool Get(const partial_key_t *key_buffer, uint8_t key_len, std::string &value_buffer) const;
  bool Delete(const partial_key_t *key_buffer, size_t key_len);

  inline size_t GetSize() const { return size_; }

#ifdef ART_BUILD_TESTS
  static void TEST_NodePtr();
#endif

 private:
  NodePtr root_;
  size_t size_;
};

struct AdaptiveRadixTree::Node4 {
  partial_key_t partial_key[4];
  NodePtr child_ptrs[4]{NodePtr()};

  NodePtr FindChild(partial_key_t key_span);
};

struct alignas(64) AdaptiveRadixTree::Node16 {
  partial_key_t partial_key[16];
  NodePtr child_ptrs[16]{NodePtr()};

  NodePtr FindChild(partial_key_t key_span);
};

struct AdaptiveRadixTree::Node48 {
  uint8_t child_indexes[256];
  NodePtr child_ptrs[48]{NodePtr()};

  NodePtr FindChild(partial_key_t key_span);
};

struct AdaptiveRadixTree::Node256 {
  NodePtr child_ptrs[256]{NodePtr()};

  NodePtr FindChild(partial_key_t key_span);
};

}