// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#include <cstdint>

#include "art/art.h"

namespace ART_NAMESPACE {

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
      case NodeType::kNode4: {
        auto node4_ptr = cur_node_ptr.GetPtr<Node4>();
        if (key_len == 0) {
          bool res = !node4_ptr->node_value.IsUndefined();
          node4_ptr->node_value.Assign(value_buffer, value_len);
          return res;
        }
        NodePtr next_node = Node4FindChild(node4_ptr, *key_buffer);
        if (next_node.IsNullptr()) {
          // TODO
//          node4_ptr->TryAddLeafNode(*key_buffer);
        }
        break;
      }
      case NodeType::kNode16:break;
      case NodeType::kNode48:break;
      case NodeType::kNode256:break;
      case NodeType::kLeafNodeWithPrefixKey: {
        auto leaf_node_ptr = cur_node_ptr.GetPtr<LeafNodeWithPrefixKey>();
        size_t mismatch_idx = leaf_node_ptr->key.CmpMismatch(key_buffer, key_len);

        if (mismatch_idx == 0) {
          // no prefix_key
          // leaf_node_ptr->key: "abc"
          // key_buffer: "def"
          auto *node4 = new Node4(leaf_node_ptr->prefix_value);
          //FIXME
          Node4TryAddLeafNode(node4, key_buffer[mismatch_idx],
                              NodePtr::NewLeafNode(key_buffer + mismatch_idx,
                                                   key_len - mismatch_idx,
                                                   value_buffer,
                                                   value_len, BufOrPtr()));
          Node4TryAddLeafNode(node4, leaf_node_ptr->key[mismatch_idx],
                              NodePtr::NewLeafNode(leaf_node_ptr->key + mismatch_idx + 1,
                                                   leaf_node_ptr->key.len - mismatch_idx - 1,
                                                   leaf_node_ptr->value, BufOrPtr()));

          delete leaf_node_ptr;
          cur_node_ptr = NodePtr(node4, NodeType::kNode4);
          return false;
        }

        Node4WithPrefixKey *node4;
        if (mismatch_idx == leaf_node_ptr->key.len) {
          assert(key_len >= leaf_node_ptr->key.len);
          if (key_len == leaf_node_ptr->key.len) {
            // same key, just update value
            leaf_node_ptr->value.Assign(value_buffer, value_len);
            return true;
          }

          // leaf_node_ptr->key: "abc"
          // key_buffer: "abcde"
          node4 = Node4WithPrefixKey::NewInline(key_buffer, mismatch_idx, leaf_node_ptr->value);
          Node4TryAddLeafNode(node4, key_buffer[mismatch_idx],
                              NodePtr::NewLeafNode(key_buffer + mismatch_idx,
                                                   key_len - mismatch_idx,
                                                   value_buffer,
                                                   value_len, BufOrPtr()));

        } else if (mismatch_idx == key_len) {
          assert(mismatch_idx < leaf_node_ptr->key.len);

          // leaf_node_ptr->key: "abcde"
          // key_buffer: "abc"
          node4 = Node4WithPrefixKey::NewInline(key_buffer, mismatch_idx, BufOrPtr(value_buffer, value_len));
          Node4TryAddLeafNode(node4, leaf_node_ptr->key[mismatch_idx],
                              NodePtr::NewLeafNode(leaf_node_ptr->key + mismatch_idx,
                                                   leaf_node_ptr->key.len - mismatch_idx,
                                                   leaf_node_ptr->value, BufOrPtr()));

        } else {
          assert(mismatch_idx < leaf_node_ptr->key.len);
          assert(mismatch_idx < key_len);

          // leaf_node_ptr->key: "abcde"
          // key_buffer: "abb"
          node4 = Node4WithPrefixKey::NewInline(key_buffer, mismatch_idx);
          Node4TryAddLeafNode(node4, key_buffer[mismatch_idx],
                              NodePtr::NewLeafNode(key_buffer + mismatch_idx,
                                                   key_len - mismatch_idx,
                                                   value_buffer,
                                                   value_len, BufOrPtr()));
          Node4TryAddLeafNode(node4, leaf_node_ptr->key[mismatch_idx],
                              NodePtr::NewLeafNode(leaf_node_ptr->key + mismatch_idx + 1,
                                                   leaf_node_ptr->key.len - mismatch_idx - 1,
                                                   leaf_node_ptr->value, BufOrPtr()));
        }
        delete leaf_node_ptr;
        cur_node_ptr = NodePtr(node4, NodeType::kNode4WithPrefixKey);
        return false;
      }
      case NodeType::kNode4WithPrefixKey:break;
      case NodeType::kNode16WithPrefixKey:break;
      case NodeType::kNode48WithPrefixKey:break;
      case NodeType::kNode256WithPrefixKey:break;
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
      case NodeType::kNode4: {
        auto *node4 = cur_node.GetPtr<Node4>();
        if (key_len == 0) {
          node4->node_value.CopyToBuffer(value_buffer);
          return true;
        }
        cur_node = Node4FindChild(node4, *key_buffer);
        break;
      }
      case NodeType::kNode16: {
        auto *node16 = cur_node.GetPtr<Node16>();
        if (key_len == 0) {
          node16->value.CopyToBuffer(value_buffer);
          return true;
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
      case NodeType::kLeafNodeWithPrefixKey: {
        auto leaf_node = cur_node.GetPtr<LeafNodeWithPrefixKey>();
        return leaf_node->GetIfMatch(key_buffer, key_len, value_buffer);
      }
      case NodeType::kNode4WithPrefixKey:break;
      case NodeType::kNode16WithPrefixKey:break;
      case NodeType::kNode48WithPrefixKey:break;
      case NodeType::kNode256WithPrefixKey:break;
    }
  }
}

bool AdaptiveRadixTree::Delete(const char *key_buffer, size_t key_len) {
  return false;
}

}
