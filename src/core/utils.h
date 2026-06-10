// Should be reviewed

#ifndef VHSM_UTILS_H
#define VHSM_UTILS_H

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vhsm::utils {

// ---------------------------------------------------------------------------
// UUID
// ---------------------------------------------------------------------------

/// Generate a random UUID v4 string in canonical form:
/// "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
/// Randomness sourced from the OS CSPRNG (getrandom / BCryptGenRandom).
/// Thread-safe; never throws.
[[nodiscard]]
std::string uuid_v4();

// ---------------------------------------------------------------------------
// Base64  (RFC 4648 §4 — standard alphabet, with padding)
// ---------------------------------------------------------------------------

/// Encode arbitrary bytes to standard Base64.
[[nodiscard]]
std::string base64_encode(std::span<const std::byte> data);

/// Decode standard Base64.
/// Returns nullopt if the input is malformed (invalid characters, bad padding,
/// length not a multiple of 4, or padding not at the end of the last group).
[[nodiscard]]
std::optional<std::vector<std::byte>> base64_decode(std::string_view s);

// ---------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------

/// Encode bytes to lowercase hexadecimal ("deadbeef…").
[[nodiscard]]
std::string hex_encode(std::span<const std::byte> data);

/// Decode a lowercase or uppercase hex string.
/// Returns nullopt if `s` has odd length or contains non-hex characters.
[[nodiscard]]
std::optional<std::vector<std::byte>> hex_decode(std::string_view s);

} // namespace vhsm::utils

#endif // VHSM_UTILS_H