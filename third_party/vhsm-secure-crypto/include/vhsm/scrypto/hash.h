#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace vhsm::scrypto {

// SHA-256 — FIPS 180-4, no OpenSSL dependency
std::array<uint8_t, 32> sha256(const uint8_t *data, size_t len);
inline std::array<uint8_t, 32> sha256(const std::vector<uint8_t> &v) {
  return sha256(v.data(), v.size());
}
inline std::array<uint8_t, 32> sha256(const std::string &s) {
  return sha256(reinterpret_cast<const uint8_t *>(s.data()), s.size());
}

std::string sha256_hex(const uint8_t *data, size_t len);
inline std::string sha256_hex(const std::vector<uint8_t> &v) {
  return sha256_hex(v.data(), v.size());
}

// SHA-384 / SHA-512 — FIPS 180-4 (SHA-512 family, truncation for 384)
std::array<uint8_t, 64> sha512(const uint8_t *data, size_t len);
inline std::array<uint8_t, 64> sha512(const std::vector<uint8_t> &v) {
  return sha512(v.data(), v.size());
}
std::array<uint8_t, 48> sha384(const uint8_t *data, size_t len);
inline std::array<uint8_t, 48> sha384(const std::vector<uint8_t> &v) {
  return sha384(v.data(), v.size());
}

// Generic hash used by p11_hash
enum class HashAlg { SHA256, SHA384, SHA512 };
std::vector<uint8_t> hash(HashAlg alg, const uint8_t *data, size_t len);
inline std::vector<uint8_t> hash(HashAlg alg, const std::vector<uint8_t> &v) {
  return hash(alg, v.data(), v.size());
}

const char *hash_name(HashAlg a) noexcept;

} // namespace vhsm::scrypto
