// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#pragma once

#include "art/art_node.h"

namespace ART_NAMESPACE {

class AdaptiveRadixTree {
 public:
  AdaptiveRadixTree();
  ~AdaptiveRadixTree();

  bool Insert(const partial_key_t *key_buffer, uint8_t key_len, const char *value_buffer, uint8_t value_len);
  bool Get(const partial_key_t *key_buffer, uint8_t key_len, std::string &value_buffer) const;
  bool Delete(const partial_key_t *key_buffer, size_t key_len);

  inline size_t GetSize() const { return size_; }

 private:
  NodePtr root_;
  size_t size_;
};

}