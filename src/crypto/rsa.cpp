/*
 * rsa.cpp — RSA via vhsm::scrypto policy wrapper (no OpenSSL EVP here).
 */
#include "rsa.h"
#include "../core/error.h"
#include "vhsm/scrypto/rsa.h"

namespace vhsm::crypto {

void rsa_free_key(RSAKeyPair &kp) noexcept {
  if (kp.key) {
    vhsm::scrypto::rsa_free({kp.key, kp.bits});
    kp.key = nullptr;
    kp.bits = 0;
  }
}

RSAKeyPair RSAUtil::generate_key(int bits) {
  VHSM_CHECK_ARG(bits >= 2048,
                 "RSAUtil::generate_key: key size must be >= 2048 bits");
  auto kp = vhsm::scrypto::rsa_generate(bits);
  return RSAKeyPair{kp.handle, kp.bits};
}

std::vector<uint8_t> RSAUtil::sign(const RSAKeyPair &key,
                                   const std::vector<uint8_t> &data) {
  VHSM_CHECK_ARG(key.key != nullptr, "RSAUtil::sign: key is null");
  return vhsm::scrypto::rsa_sign({key.key, key.bits}, data,
                                 vhsm::scrypto::RsaPadding::PKCS1, "SHA256");
}

bool RSAUtil::verify(const RSAKeyPair &key, const std::vector<uint8_t> &data,
                     const std::vector<uint8_t> &signature) {
  VHSM_CHECK_ARG(key.key != nullptr, "RSAUtil::verify: key is null");
  try {
    return vhsm::scrypto::rsa_verify({key.key, key.bits}, data, signature,
                                     vhsm::scrypto::RsaPadding::PKCS1,
                                     "SHA256");
  } catch (const std::exception &) {
    // scrypto throws on backend error; treat as verification error
    throw;
  }
}
} // namespace vhsm::crypto
