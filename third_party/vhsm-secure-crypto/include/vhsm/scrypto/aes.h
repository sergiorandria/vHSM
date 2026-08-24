#pragma once
#include <array>
#include <cstdint>
#include <vector>

namespace vhsm::scrypto {

// AES-256 core — FIPS 197, constant-time S-box (no T-tables)
struct Aes256Key {
  std::array<uint32_t, 60> rk; // round keys
  static Aes256Key expand(const uint8_t key[32]);
};

void aes256_encrypt_block(const Aes256Key &rk, const uint8_t in[16],
                          uint8_t out[16]);
void aes256_decrypt_block(const Aes256Key &rk, const uint8_t in[16],
                          uint8_t out[16]);

// ECB single-block helpers (for CTR_DRBG and KeyWrap RFC3394)
// No padding — caller ensures 16-byte blocks.
void aes256_ecb_encrypt_block(const uint8_t key[32], const uint8_t in[16],
                              uint8_t out[16]);
void aes256_ecb_decrypt_block(const uint8_t key[32], const uint8_t in[16],
                              uint8_t out[16]);

} // namespace vhsm::scrypto
