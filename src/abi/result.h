#ifndef VHSM_ABI_RESULT_H
#define VHSM_ABI_RESULT_H

#include "export.h"
#include <expected>
#include <string>
#include <system_error>

// Result<T> — nodiscard, move-only, exception-free carrier for fallible ABI
// calls. Every public function that can fail returns this; the compiler
// rejects `foo();` without checking because `Result` is `[[nodiscard]]`.
// Internally it is `std::expected<T, std::error_code>` (C++23) so callers can
// `if (!r) return r.error();` without throwing across the ABI.

VHSM_ABI_NAMESPACE_BEGIN

template <typename T>
using Result = std::expected<T, std::error_code>;

using Status = std::error_code; // void-result alias: Result<void> is Status

// Helpers — keep call sites terse and nodiscard-propagating.
template <typename T>
VHSM_NODISCARD inline Result<T> ok(T&& v) {
  return Result<T>(std::forward<T>(v));
}
inline Result<void> ok() { return Result<void>{}; }

template <typename T>
VHSM_NODISCARD inline Result<T> err(std::error_code ec) {
  return std::unexpected(ec);
}
inline Result<void> err(std::error_code ec) {
  return std::unexpected(ec);
}

// Error category base for domain errors (e.g. CKR_* → std::error_code).
class VHSM_HIDDEN VHSMErrorCategory : public std::error_category {
public:
  const char* name() const noexcept override { return "vhsm"; }
  std::string message(int ev) const override;
};

VHSM_ABI_NAMESPACE_END

#endif // VHSM_ABI_RESULT_H
