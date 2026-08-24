#pragma once
#include "hash.h"
#include <array>
#include <cstdint>
#include <vector>

namespace vhsm::scrypto {

// HMAC-SHA256 — RFC 2104, constant-time, no OpenSSL HMAC()
std::array<uint8_t, 32> hmac_sha256(const uint8_t *key, size_t key_len,
                                    const uint8_t *data, size_t data_len);
inline std::array<uint8_t, 32> hmac_sha256(const std::vector<uint8_t> &key,
                                           const std::vector<uint8_t> &data) {
  return hmac_sha256(key.data(), key.size(), data.data(), data.size());
}

// HMAC with variable hash (for HKDF/PBKDF2 flexibility if needed)
std::vector<uint8_t> hmac(HashAlg alg, const uint8_t *key, size_t key_len,
                          const uint8_t *data, size_t data_len);

} // namespace vhsm::scrypto
