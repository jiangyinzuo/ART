// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#include "util.h"

namespace ART_NAMESPACE {

size_t MemCmpMismatch(const char *buf1, const char *buf2, size_t n) {
  int i = 0;
  while (*buf1++ == *buf2++) {
    if (++i == n) {
      return n;
    }
  }
  return i;
}

}