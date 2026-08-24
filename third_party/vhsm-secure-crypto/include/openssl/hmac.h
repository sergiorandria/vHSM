#pragma once
#ifdef VHSM_OPENSSL_SHIM
#include "openssl/evp.h"
#include <stddef.h>
#ifdef __cplusplus
#include "vhsm/scrypto/hmac.h"
#include <string.h>
inline unsigned char *HMAC(const void *evp_md, const void *key, int key_len,
                           const unsigned char *d, size_t n, unsigned char *md,
                           unsigned int *md_len) {
  (void)evp_md;
  auto out = vhsm::scrypto::hmac_sha256((const unsigned char *)key,
                                        (size_t)key_len, d, n);
  if (md) {
    memcpy(md, out.data(), out.size());
    if (md_len)
      *md_len = (unsigned int)out.size();
    return md;
  }
  static unsigned char buf[64];
  memcpy(buf, out.data(), out.size());
  if (md_len)
    *md_len = (unsigned int)out.size();
  return buf;
}
#else
unsigned char *HMAC(const void *evp_md, const void *key, int key_len,
                    const unsigned char *d, size_t n, unsigned char *md,
                    unsigned int *md_len);
#endif
#else
#include_next <openssl/hmac.h>
#endif
