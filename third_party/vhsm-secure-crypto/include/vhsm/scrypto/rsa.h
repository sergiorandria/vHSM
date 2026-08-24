#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace vhsm::scrypto {

// RSA policy — hardened wrapper around math backend
// Rejects keys <2048 bits, enforces secure padding, constant-time checks.

enum class RsaPadding {
  PKCS1,       // RSASSA-PKCS1-v1_5 for sign/verify (allowed for compat)
  PSS,         // RSASSA-PSS (preferred)
  OAEP_SHA256, // RSAES-OAEP with SHA-256 (only OAEP allowed for encrypt)
  NoPadding    // raw RSA — only for CKM_RSA_X_509, checks length
};

struct RsaKeyPair {
  // Opaque handle — backend is OpenSSL EVP_PKEY* when VHSM_SCRYPTO_HAS_OPENSSL,
  // or internal bignum when pure. Caller must free via rsa_free.
  void *handle = nullptr;
  int bits = 0;
};

void rsa_free(RsaKeyPair kp) noexcept;

RsaKeyPair rsa_generate(int bits); // bits must be 2048/3072/4096, else throws
std::vector<uint8_t> rsa_sign(const RsaKeyPair &key,
                              const std::vector<uint8_t> &data, RsaPadding pad,
                              const std::string &hash_alg = "SHA256");
bool rsa_verify(const RsaKeyPair &key, const std::vector<uint8_t> &data,
                const std::vector<uint8_t> &sig, RsaPadding pad,
                const std::string &hash_alg = "SHA256");
std::vector<uint8_t> rsa_encrypt(const RsaKeyPair &key,
                                 const std::vector<uint8_t> &pt,
                                 RsaPadding pad);
std::vector<uint8_t> rsa_decrypt(const RsaKeyPair &key,
                                 const std::vector<uint8_t> &ct,
                                 RsaPadding pad);

// Interop with existing vHSM EVP_PKEY* code — when OpenSSL backend is present,
// these convert. In pure mode they are no-ops.
void *rsa_handle_from_evp(void *evp_pkey) noexcept;
void *evp_from_rsa_handle(void *handle) noexcept;

} // namespace vhsm::scrypto
