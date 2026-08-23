// Should be reviewed

#ifndef VHSM_UTILS_H
#define VHSM_UTILS_H

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "../abi/error.h"
#include "../abi/result.h"
#include "macros.h"

namespace vhsm::utils {

/// WHY try_uuid_v4 returns Result: The original `uuid_v4()` throws on
/// `BCryptGenRandom`/`getrandom` failure, which would unwind across the
/// PKCS#11 C ABI boundary (`C_Sign` is `extern "C"` and must not throw).
/// `try_uuid_v4()` is the ABI-friendly overload that carries the error as
/// `std::error_code` in `vhsm::v1::Result<std::string>` so the caller can
/// `if (!r) return CKR_DEVICE_ERROR` without catching, and the compiler
/// enforces handling via `[[nodiscard]]` on `Result`.
VHSM_NODISCARD vhsm::v1::Result<std::string> try_uuid_v4() noexcept;

/// Generate a random UUID v4 string in canonical form:
/// "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
/// Randomness sourced from the OS CSPRNG (getrandom / BCryptGenRandom).
/// Thread-safe; never throws.
_VHSMXX_NODISCARD
std::string uuid_v4();

/// Base64  (RFC 4648 §4 — standard alphabet, with padding)
/// Encode arbitrary bytes to standard Base64.
_VHSMXX_NODISCARD
std::string base64_encode(std::span<const std::byte> data);

/// Decode standard Base64.
/// Returns nullopt if the input is malformed (invalid characters, bad padding,
/// length not a multiple of 4, or padding not at the end of the last group).
_VHSMXX_NODISCARD
std::optional<std::vector<std::byte>> base64_decode(std::string_view s);

/// Encode bytes to lowercase hexadecimal ("deadbeef…").
_VHSMXX_NODISCARD
std::string hex_encode(std::span<const std::byte> data);

/// Decode a lowercase or uppercase hex string.
/// Returns nullopt if `s` has odd length or contains non-hex characters.
_VHSMXX_NODISCARD
std::optional<std::vector<std::byte>> hex_decode(std::string_view s);

} // namespace vhsm::utils

#endif // VHSM_UTILS_H