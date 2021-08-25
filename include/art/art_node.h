// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#pragma once

#include <cstdint>

#include "art/art_namespace.h"

namespace ART_NAMESPACE {

enum class NodeType {
  kNode4 = 0,
  kNode16 = 1,
  kNode48 = 2,
  kNode256 = 3,
};

// Wrapper of `Node4`, `Node16`, `Node48` and `Node256`'s pointer.
// Pointer MUST be aligned with at least 4 bytes (remaining 2 bits for NodeType).
struct NodePtr {

  NodePtr(void *ptr, NodeType tp) : bits_(reinterpret_cast<uint64_t>(ptr) | static_cast<uint64_t>(tp)) {
    assert((reinterpret_cast<uint64_t>(ptr) & 0b11) == 0);
  }

  inline void *GetPtr() const {
    return reinterpret_cast<void *>(bits_ & (UINT64_MAX - 0b11));
  }

  inline NodeType GetNodeType() const {
    return static_cast<NodeType>(bits_ & 0b11);
  }

  inline void SetPtr(void *ptr) {
    auto n = reinterpret_cast<uint64_t>(ptr);
    assert((n & 0b11) == 0);
    bits_ = n | (bits_ & 0b11);
  }

  inline void SetNodeType(NodeType tp) {
    bits_ = (bits_ & (UINT64_MAX - 0b11)) | static_cast<uint64_t>(tp);
  }

 private:
  uint64_t bits_;
};

static_assert(sizeof(NodePtr) == sizeof(uint64_t));

using partial_key_t = uint8_t;

struct Node4 {
  partial_key_t partial_key[4];
  NodePtr child_ptrs[4];
};

static_assert(alignof(Node4) >= 4);

struct Node16 {
  partial_key_t partial_key[16];
  NodePtr child_ptrs[16];
};

static_assert(alignof(Node16) >= 4);

struct Node48 {
  uint8_t child_indexes[256];
  NodePtr child_ptrs[48];
};

static_assert(alignof(Node16) >= 4);

struct Node256 {
  NodePtr child_ptrs[256];
};

static_assert(alignof(NodePtr) >= 4);

}