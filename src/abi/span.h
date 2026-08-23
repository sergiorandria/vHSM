#ifndef VHSM_ABI_SPAN_H
#define VHSM_ABI_SPAN_H

#include "export.h"
#include <cstddef>
#include <span>

// Span — bounds-checked, non-owning view. The ABI never takes raw
// (ptr,len) pairs; it takes `span<const std::byte>` so the compiler can
// prove bounds and LTO can elide length checks.

VHSM_ABI_NAMESPACE_BEGIN

template <typename T> using Span = std::span<T>;

using ByteSpan = std::span<const std::byte>;
using MutableByteSpan = std::span<std::byte>;

VHSM_ABI_NAMESPACE_END

#endif // VHSM_ABI_SPAN_H
