// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#pragma once
#include <cstddef>
#include <string>

#include "art/art_node.h"
#include "art/art_namespace.h"

namespace ART_NAMESPACE {

class AdaptiveRadixTree {
 public:
  AdaptiveRadixTree() : root_(nullptr, NodeType::kNode4), size_(0) {}

  bool Insert(const char *key_buffer, size_t key_len, const char *value_buffer, size_t value_len);
  void Get(const char *key_buffer, size_t key_len, std::string &value_buffer) const;
  bool Delete(const char *key_buffer, size_t key_len);

  inline size_t GetSize() const { return size_; }
 private:
  NodePtr root_;
  size_t size_;
};

}