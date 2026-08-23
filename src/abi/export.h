#ifndef VHSM_ABI_EXPORT_H
#define VHSM_ABI_EXPORT_H

#include "../core/macros.h"

// WHY default visibility is hidden: On ELF, every non-static symbol is
// exported by default, which leaks internal helpers (e.g., SecureBuffer's
// memcpy) into the dynamic symbol table. An attacker with code-execution-
// adjacent access can then LD_PRELOAD a malicious `memcpy` and interpose
// secret copies. Building with -fvisibility=hidden and marking only the
// intentional ABI surface VHSM_API (default) keeps the .so's export table
// minimal, lets LTO devirtualize hidden symbols, and makes `nm -D` auditable.
// WHY Windows needs dllexport/dllimport: MSVC has no -fvisibility; the
// export table is opt-in via __declspec. VHSM_BUILDING_DLL controls which
// side of the import/export pair we are on.

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

// WHY nodiscard on every fallible Result: vHSM is a security boundary; a
// caller that writes `ledger->submit(rec);` without checking the returned
// `Result<void>` silently drops a ledger anchoring failure and the audit trail
// diverges. `[[nodiscard]]` turns that into -Werror=unused-result, so the
// compiler, not code review, enforces handling. MSVC spells the attribute
// without the extra brackets that GCC allows, hence the three-way check.
#ifndef VHSM_NODISCARD
#if defined(__GNUC__) || defined(__clang__) || defined(_MSC_VER)
#define VHSM_NODISCARD [[nodiscard]]
#else
#define VHSM_NODISCARD
#endif
#endif

// WHY noinline + hidden for secret copies: The compiler is entitled to
// inline a `memcpy` of a KEK and then eliminate the wipe as a dead store.
// Marking the copy `noinline` and `hidden` forces an out-of-line, non-
// interposable call (see SecureBuffer::__v_sb_write) so LD_PRELOAD cannot
// replace it and LTO cannot reason about the wipe's liveness. Without this,
// a single -O3 build could keep key material in a register.
// Noinline + hidden — for secret copies (SecureBuffer, KEK) so LD_PRELOAD
// cannot interpose the memcpy.
#if defined(__GNUC__) || defined(__clang__)
#define VHSM_NOINLINE_HIDDEN __attribute__((noinline, visibility("hidden")))
#else
#define VHSM_NOINLINE_HIDDEN
#endif

// WHY versioned inline namespace: PKCS#11 is a stable C ABI, but the C++
// layers (TokenSnapshot, ISignatureStore) will evolve. An inline namespace
// `v1` lets us ship `v2` with breaking changes while keeping `v1` symbols
// linkable for old binaries (dual ABI). Consumers write `vhsm::v1::Foo` for
// pinning or `vhsm::Foo` for "current" via the alias below. Bumping the
// inline namespace is cheaper than a SOVERSION bump and works on Windows
// where SOVERSION is meaningless.
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
