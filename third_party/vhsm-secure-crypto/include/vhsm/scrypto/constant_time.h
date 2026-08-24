#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace vhsm::scrypto {

// Constant-time equality — returns true iff a==b, no early exit, no branching
// on data.
inline bool constant_time_eq(const uint8_t *a, const uint8_t *b,
                             size_t len) noexcept {
  uint8_t diff = 0;
  for (size_t i = 0; i < len; ++i)
    diff |= a[i] ^ b[i];
  return diff == 0;
}
inline bool constant_time_eq(const std::vector<uint8_t> &a,
                             const std::vector<uint8_t> &b) noexcept {
  if (a.size() != b.size())
    return false;
  return constant_time_eq(a.data(), b.data(), a.size());
}
// For hex strings (RowIntegrity) — compare without leaking length via early
// exit on size mismatch size mismatch returns false immediately (size is not
// secret in vHSM), content is constant-time.
inline bool constant_time_eq_str(const std::string &a,
                                 const std::string &b) noexcept {
  if (a.size() != b.size())
    return false;
  return constant_time_eq(reinterpret_cast<const uint8_t *>(a.data()),
                          reinterpret_cast<const uint8_t *>(b.data()),
                          a.size());
}

} // namespace vhsm::scrypto
