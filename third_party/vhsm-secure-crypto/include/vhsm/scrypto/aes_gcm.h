#pragma once
#include <cstdint>
#include <vector>

namespace vhsm::scrypto {

struct GcmResult {
  std::vector<uint8_t> ciphertext;
  std::vector<uint8_t> nonce; // 12 bytes
  std::vector<uint8_t> tag;   // 16 bytes
};

// AES-256-GCM — authenticated encryption
// encrypt generates 12-byte nonce via SecureRNG, tag 16 bytes
// decrypt verifies tag in constant-time, throws on failure (fail-closed)
GcmResult aes256_gcm_encrypt(const std::vector<uint8_t> &key,
                             const std::vector<uint8_t> &plaintext,
                             const std::vector<uint8_t> &aad = {});
std::vector<uint8_t> aes256_gcm_decrypt(const std::vector<uint8_t> &key,
                                        const GcmResult &data,
                                        const std::vector<uint8_t> &aad = {});
// Low-level with caller-provided nonce (for Vault, tests)
GcmResult aes256_gcm_encrypt_with_nonce(const std::vector<uint8_t> &key,
                                        const std::vector<uint8_t> &nonce,
                                        const std::vector<uint8_t> &plaintext,
                                        const std::vector<uint8_t> &aad = {});
std::vector<uint8_t> aes256_gcm_decrypt_with_nonce(
    const std::vector<uint8_t> &key, const std::vector<uint8_t> &nonce,
    const std::vector<uint8_t> &tag, const std::vector<uint8_t> &ciphertext,
    const std::vector<uint8_t> &aad = {});

} // namespace vhsm::scrypto
