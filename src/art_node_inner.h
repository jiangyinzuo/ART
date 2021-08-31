// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#pragma once

#include "art/art_node.h"

namespace ART_NAMESPACE {

template<class T>
concept NodeConcept = requires(T t) {
  { t.node_value } -> std::same_as<ValueBufOrPtr &>;
  { t.pre_kv } -> std::same_as<PrefixKeyValueBuf &>;
};

inline void NodeFree(void* node) {
  free(node);
}

}