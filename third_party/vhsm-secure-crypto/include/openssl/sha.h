#pragma once
#ifdef VHSM_OPENSSL_SHIM
#include <stddef.h>
#define SHA256_DIGEST_LENGTH 32
#define SHA384_DIGEST_LENGTH 48
#define SHA512_DIGEST_LENGTH 64
#define SHA_DIGEST_LENGTH 20
#ifdef __cplusplus
extern "C" {
#endif
static inline unsigned char *SHA256(const unsigned char *d, size_t n,
                                    unsigned char *md) {
  extern void vhsm_sha256_impl(const unsigned char *, size_t, unsigned char *);
  vhsm_sha256_impl(d, n, md);
  return md;
}
#ifdef __cplusplus
}
#endif
// Also provide SHA256 via scrypto
#ifdef __cplusplus
#include "vhsm/scrypto/hash.h"
inline void vhsm_sha256_impl(const unsigned char *d, size_t n,
                             unsigned char *out) {
  auto h = vhsm::scrypto::sha256(d, n);
  memcpy(out, h.data(), 32);
}
#endif
#else
#include_next <openssl/sha.h>
#endif
