// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#include <cstdint>

#include "art/art.h"
#include "art_node_inner.h"

namespace ART_NAMESPACE {

template<NodeConcept Node>
NodePtr NewNode4AndAppend2Children(Node *node,
                                   const partial_key_t *key_buffer,
                                   uint8_t key_len,
                                   size_t mismatch_idx,
                                   const char *value_buffer,
                                   uint8_t value_len) {

  // no prefix_key
  // leaf_node_ptr->pre_kv: "abc"
  // key_buffer: "def"
  auto *node4 = Node4::New(*node->pre_kv.GetValueBufOrPtr());

  // append newly inserted child node
  node4->TryAppendChild(key_buffer[mismatch_idx],
                        NodePtr::NewLeafNode(key_buffer + mismatch_idx + 1,
                                             key_len - mismatch_idx - 1,
                                             value_buffer,
                                             value_len, ValueBufOrPtr()));

  // append old node
  partial_key_t k = node->pre_kv.GetKeyBuf()[mismatch_idx];
  node4->TryAppendChild(k, node->ToChildNode(mismatch_idx));

  return NodePtr(node4, NodeType::kNode4, false);
}

template<NodeConcept Node>
bool MergeNode(NodePtr &cur_node_ptr,
               const partial_key_t *&key_buffer,
               uint8_t &key_len,
               const char *value_buffer,
               uint8_t value_len) {
  auto *old_node = cur_node_ptr.GetPtr<Node>();
  size_t mismatch_idx = old_node->pre_kv.KeyCmpMismatch(key_buffer, key_len);

  if (mismatch_idx == 0) {
    cur_node_ptr =
        NewNode4AndAppend2Children(old_node, key_buffer, key_len, mismatch_idx, value_buffer, value_len);
    key_buffer += key_len;
    key_len = 0;
    return false;
  }

  // 4 cases
  if (mismatch_idx == old_node->pre_kv.GetKeyLen()) {
    if (key_len == old_node->pre_kv.GetKeyLen()) {
      // same key, just update value
      ValueBufOrPtr *prefix_value_buf = old_node->pre_kv.GetValueBufOrPtr();
      key_buffer += key_len;
      key_len = 0;
      return prefix_value_buf->Update(value_buffer, value_len);;
    }

    // old_node: "abc"
    // key_buffer: "abcde"
    key_buffer += mismatch_idx;
    key_len -= mismatch_idx;
    assert(key_len > 0);
    return false;
  } else if (mismatch_idx == key_len) {
    assert(mismatch_idx < old_node->pre_kv.GetKeyLen());
    // old_node->pre_kv: "abcde"
    // key_buffer: "abc"
    // TODO
  } else {
    assert(mismatch_idx < old_node->pre_kv.GetKeyLen());
    assert(mismatch_idx < key_len);

    // old_node->pre_kv: "abcde"
    // key_buffer: "abb"
    // TODO
  }
  return false;
}

bool LeafMergeNode(NodePtr &cur_node_ptr,
                   const partial_key_t *key_buffer,
                   uint8_t key_len,
                   const char *value_buffer,
                   uint8_t value_len) {
  auto *old_node = cur_node_ptr.GetPtr<LeafNodeWithPrefixKey>();
  size_t mismatch_idx = old_node->pre_kv.KeyCmpMismatch(key_buffer, key_len);

  if (mismatch_idx == 0) {
    cur_node_ptr =
        NewNode4AndAppend2Children(old_node, key_buffer, key_len, mismatch_idx, value_buffer, value_len);
    return false;
  }

  Node4 *node4;
  // 4 cases
  if (mismatch_idx == old_node->pre_kv.GetKeyLen()) {
    assert(key_len >= old_node->pre_kv.GetKeyLen());
    if (key_len == old_node->pre_kv.GetKeyLen()) {
      // same key, just update value
      old_node->node_value.Assign(value_buffer, value_len);
      return true;
    }

    // old_node->pre_kv: "abc"
    // key_buffer: "abcde"
    node4 = Node4::NewWithPrefixKey(key_buffer, mismatch_idx, old_node->node_value);
    node4->TryAppendChild(key_buffer[mismatch_idx],
                          NodePtr::NewLeafNode(key_buffer + mismatch_idx,
                                               key_len - mismatch_idx,
                                               value_buffer,
                                               value_len, ValueBufOrPtr()));
  } else if (mismatch_idx == key_len) {
    assert(mismatch_idx < old_node->pre_kv.GetKeyLen());

    // old_node->pre_kv: "abcde"
    // key_buffer: "abc"
    node4 = Node4::NewWithPrefixKey(key_buffer, mismatch_idx, ValueBufOrPtr(value_buffer, value_len));
    node4->TryAppendChild(old_node->pre_kv.GetKeyBuf()[mismatch_idx],
                          NodePtr::NewLeafNode(old_node->pre_kv.GetKeyBuf() + mismatch_idx + 1,
                                               old_node->pre_kv.GetKeyLen() - mismatch_idx - 1,
                                               old_node->node_value, ValueBufOrPtr()));

  } else {
    assert(mismatch_idx < old_node->pre_kv.GetKeyLen());
    assert(mismatch_idx < key_len);

    // old_node->pre_kv: "abcde"
    // key_buffer: "abb"
    node4 = Node4::NewWithPrefixKey(key_buffer, mismatch_idx);
    node4->TryAppendChild(key_buffer[mismatch_idx],
                          NodePtr::NewLeafNode(key_buffer + mismatch_idx + 1,
                                               key_len - mismatch_idx - 1,
                                               value_buffer,
                                               value_len, ValueBufOrPtr()));
    node4->TryAppendChild(old_node->pre_kv.GetKeyBuf()[mismatch_idx],
                          NodePtr::NewLeafNode(old_node->pre_kv.GetKeyBuf() + mismatch_idx + 1,
                                               old_node->pre_kv.GetKeyLen() - mismatch_idx - 1,
                                               old_node->node_value, ValueBufOrPtr()));
  }
  NodeFree(cur_node_ptr.GetPtr<void *>());
  cur_node_ptr = NodePtr(node4, NodeType::kNode4, true);
  return false;
}

AdaptiveRadixTree::AdaptiveRadixTree() : root_(NodePtr()), size_(0) {}

bool AdaptiveRadixTree::Insert(const partial_key_t *key_buffer,
                               uint8_t key_len,
                               const char *value_buffer,
                               uint8_t value_len) {
  for (NodePtr &cur_node_ptr = root_;;) {
    switch (cur_node_ptr.GetNodeType()) {
      case NodeType::kNullPtr: {
        if (key_len == 0) {
          cur_node_ptr.ToInlineLeafNode(value_buffer, value_len);
        } else {
          cur_node_ptr =
              NodePtr::NewLeafNode(key_buffer, key_len, value_buffer, value_len, cur_node_ptr.ToBufOrPtr());
        }
        return false;
      }

      case NodeType::kInlineLeafNode:
        if (key_len == 0) {
          cur_node_ptr.ToInlineLeafNode(value_buffer, value_len);
          return true;
        } else {
          cur_node_ptr =
              NodePtr::NewLeafNode(key_buffer, key_len, value_buffer, value_len, cur_node_ptr.ToBufOrPtr());
          return false;
        }
      case NodeType::kLeafNodeWithPrefixKey: {
        return LeafMergeNode(cur_node_ptr,
                             key_buffer,
                             key_len,
                             value_buffer,
                             value_len);
      }
      case NodeType::kNode4: {
        if (key_len == 0) {
          // update prefix value
          auto node4_ptr = cur_node_ptr.GetPtr<Node4>();
          return node4_ptr->node_value.Update(value_buffer, value_len);
        }

        if (cur_node_ptr.HasPrefixKey()) {
          bool res = MergeNode<Node4>(cur_node_ptr, key_buffer, key_len,
                                      value_buffer, value_len);
          if (key_len == 0) {
            return res;
          }
        }

        auto node4_ptr = cur_node_ptr.GetPtr<Node4>();
        NodePtr next_node = node4_ptr->FindChild(*key_buffer);
        if (next_node.IsNullptr()) {
          // child not found, stop search and insert leaf node
          if (!node4_ptr->TryAppendChild(
              *key_buffer,
              NodePtr::NewLeafNode(key_buffer + 1,
                                   key_len - 1,
                                   value_buffer,
                                   value_len,
                                   ValueBufOrPtr()))) {
            // TODO expand
            throw "not implemented";
          }
          return false;
        }

        // child found, continue searching
        cur_node_ptr = next_node;
        break;
      }
      case NodeType::kNode16:break;
      case NodeType::kNode48:break;
      case NodeType::kNode256:break;
    }
  }
}

AdaptiveRadixTree::~AdaptiveRadixTree() {
  // TODO
}

bool AdaptiveRadixTree::Get(const char *key_buffer, uint8_t key_len, std::string &value_buffer) const {
  NodePtr cur_node = root_;

  for (;;) {
    switch (cur_node.GetNodeType()) {
      case NodeType::kNullPtr:return false;
      case NodeType::kInlineLeafNode: {
        cur_node.GetLeafValue(value_buffer);
        return true;
      }
      case NodeType::kLeafNodeWithPrefixKey: {
        auto leaf_node = cur_node.GetPtr<LeafNodeWithPrefixKey>();
        return leaf_node->GetIfMatch(key_buffer, key_len, value_buffer);
      }
      case NodeType::kNode4: {
        auto *node4 = cur_node.GetPtr<Node4>();
        if (key_len == 0) {
          return node4->node_value.CopyToBuffer(value_buffer);
        }
        if (cur_node.HasPrefixKey() && node4->pre_kv.MatchPrefixKey(key_buffer, key_len)) {
          return node4->pre_kv.GetValueBufOrPtr()->CopyToBuffer(value_buffer);
        }
        cur_node = node4->FindChild(*key_buffer);
        ++key_buffer;
        --key_len;
        break;
      }
      case NodeType::kNode16: {
        auto *node16 = cur_node.GetPtr<Node16>();
        if (key_len == 0) {
          return node16->node_value.CopyToBuffer(value_buffer);
        }
        // TODO
        break;
      }
      case NodeType::kNode48: {
        auto *node48 = cur_node.GetPtr<Node48>();
        cur_node = node48->FindChild(*key_buffer);
        break;
      }
      case NodeType::kNode256: {
        auto *node256 = cur_node.GetPtr<Node256>();
        cur_node = node256->FindChild(*key_buffer);
        break;
      }
    }
  }
}

bool AdaptiveRadixTree::Delete(const char *key_buffer, size_t key_len) {
  return false;
}

}
