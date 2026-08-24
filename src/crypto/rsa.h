/*
 * rsa.h
 *
 * RSA wrapper declarations backed by vhsm::scrypto (hardened clone).
 * Provides key generation, signing and verification helpers. The key handle
 * is an opaque scrypto handle; callers free it with rsa_free_key().
 *
 * Policy enforced by scrypto (see third_party/vhsm-secure-crypto):
 * - bits must be 2048/3072/4096
 * - sign uses SHA-256 with PKCS#1 v1.5 or PSS
 */
#ifndef VHSM_CRYPTO_RSA
#define VHSM_CRYPTO_RSA

#include <cstdint>
#include <vector>

namespace vhsm::crypto {

// Opaque RSA key handle produced by generate_key. Free with rsa_free_key().
struct RSAKeyPair {
  void *key = nullptr;
  int bits = 0;
};

void rsa_free_key(RSAKeyPair &kp) noexcept;

class RSAUtil {
public:
  static RSAKeyPair generate_key(int bits);
  static std::vector<uint8_t> sign(const RSAKeyPair &key,
                                   const std::vector<uint8_t> &data);
  static bool verify(const RSAKeyPair &key, const std::vector<uint8_t> &data,
                     const std::vector<uint8_t> &signature);
};
} // namespace vhsm::crypto
#endif // VHSM_CRYPTO_RSA
