#pragma once
#ifdef VHSM_OPENSSL_SHIM
#include <stddef.h>
#ifdef __cplusplus
#include "vhsm/scrypto/hash.h"
#include "vhsm/scrypto/kdf.h"
#include <string>
#include <vector>
inline int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
                             const unsigned char *salt, int saltlen, int iter,
                             const void *digest, int keylen,
                             unsigned char *out) {
  (void)digest;
  try {
    std::string pw(pass, passlen);
    std::vector<unsigned char> s(salt, salt + saltlen);
    auto res = vhsm::scrypto::pbkdf2_hmac_sha256(pw, s, (uint32_t)iter,
                                                 (size_t)keylen);
    memcpy(out, res.data(), res.size());
    return 1;
  } catch (...) {
    return 0;
  }
}
#endif
#else
#include_next <openssl/kdf.h>
#endif
