#pragma once
// Drop-in shim: maps a subset of OpenSSL EVP API used by vHSM to vhsm::scrypto.
// Allows gradual migration without rewriting every call site at once.
// When VHSM_USE_SECURE_CRYPTO=ON, this header redirects to secure impls.
// When OFF, it simply includes <openssl/evp.h>.

#include "aes_gcm.h"
#include "constant_time.h"
#include "hash.h"
#include "hmac.h"
#include "mem.h"

// Minimal EVP_MD_CTX compatibility for existing CryptoEngine/RSA/ECC code.
// New code should use vhsm::scrypto::* directly.
namespace vhsm::scrypto::compat {
struct Sha256Ctx {
  void init();
  void update(const uint8_t *d, size_t n);
  void final(uint8_t out[32]);
  uint32_t h[8];
  uint64_t total_len = 0;
  uint8_t buf[64];
  size_t buflen = 0;
};
} // namespace vhsm::scrypto::compat

#ifdef VHSM_USE_SECURE_CRYPTO
#ifndef OPENSSL_VERSION_NUMBER
#define OPENSSL_VERSION_NUMBER 0x30000000L
#endif
inline void OPENSSL_cleanse(void *p, size_t l) { vhsm::scrypto::cleanse(p, l); }
#else
// When not using secure crypto, also expose OpenSSL headers for fallback code
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#endif
