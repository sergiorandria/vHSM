#ifndef VHSM_ABI_EXPORT_H
#define VHSM_ABI_EXPORT_H

#include "../core/macros.h"

// VHSM_API — default visibility (exported). Everything else is hidden by
// -fvisibility=hidden, so only these symbols appear in the .so/.dll.
// VHSM_HIDDEN — explicitly hidden (internal, test-only, or LTO devirtualizable).
#if defined(_WIN32)
#if defined(VHSM_BUILDING_DLL)
#define VHSM_API __declspec(dllexport)
#define VHSM_HIDDEN
#else
#define VHSM_API __declspec(dllimport)
#define VHSM_HIDDEN
#endif
#else
#define VHSM_API __attribute__((visibility("default")))
#define VHSM_HIDDEN __attribute__((visibility("hidden")))
#endif

// Nodiscard — force callers to handle fallible results. MSVC needs the
// attribute spelled without the extra brackets that GCC allows.
#ifndef VHSM_NODISCARD
#if defined(__GNUC__) || defined(__clang__) || defined(_MSC_VER)
#define VHSM_NODISCARD [[nodiscard]]
#else
#define VHSM_NODISCARD
#endif
#endif

// Noinline + hidden — for secret copies (SecureBuffer, KEK) so LD_PRELOAD
// cannot interpose the memcpy.
#if defined(__GNUC__) || defined(__clang__)
#define VHSM_NOINLINE_HIDDEN __attribute__((noinline, visibility("hidden")))
#else
#define VHSM_NOINLINE_HIDDEN
#endif

// Versioned ABI namespace. Consumers write `vhsm::v1::Foo`; `vhsm::Foo` is an
// alias to the current version. Bumping the inline namespace to `v2` keeps
// `v1` linkable for existing binaries (dual ABI).
#define VHSM_ABI_VERSION_MAJOR 1
#define VHSM_ABI_VERSION_MINOR 0

#define VHSM_ABI_NAMESPACE_BEGIN \
  namespace vhsm {               \
  inline namespace v1 {

#define VHSM_ABI_NAMESPACE_END \
  }                            \
  } // namespace vhsm

// The unversioned alias `vhsm::Foo` → `vhsm::v1::Foo` (always points at current).
// New major versions add `inline namespace v2` and keep `v1` for compat.

#endif // VHSM_ABI_EXPORT_H
