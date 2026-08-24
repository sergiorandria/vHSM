#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace vhsm::scrypto {

// PBKDF2-HMAC-SHA256 — RFC 2898, constant-time, hardened defaults
// iterations must be >= 100000 in production; tests may pass lower but logs
// warning.
std::vector<uint8_t> pbkdf2_hmac_sha256(const std::string &password,
                                        const std::vector<uint8_t> &salt,
                                        uint32_t iterations, size_t out_len);

// HKDF-SHA256 — RFC 5869 Extract+Expand
std::vector<uint8_t> hkdf_sha256(const std::vector<uint8_t> &ikm,
                                 const std::vector<uint8_t> &salt,
                                 const std::vector<uint8_t> &info,
                                 size_t out_len);

// vHSM-specific: DB HMAC key derived from vault KEK (stable, no random salt)
std::vector<uint8_t> derive_db_hmac_key(const std::vector<uint8_t> &vault_kek);

} // namespace vhsm::scrypto
