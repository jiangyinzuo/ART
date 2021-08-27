// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

#pragma once

#include <cstddef>
#include "art/art_namespace.h"

namespace ART_NAMESPACE {

// Return the first mismatch index.
// If the first "n" characters of "buf1" and "buf2" are equal, return "n".
size_t MemCmpMismatch(const char *buf1, const char *buf2, size_t n);

}