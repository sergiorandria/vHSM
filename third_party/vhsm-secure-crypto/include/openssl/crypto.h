#pragma once
#ifdef VHSM_OPENSSL_SHIM
#include <stddef.h>
#include <stdlib.h>
#ifdef __cplusplus
#include "vhsm/scrypto/mem.h"
extern "C" {
#endif
static inline void OPENSSL_cleanse(void *ptr, size_t len) {
  vhsm::scrypto::cleanse(ptr, len);
}
static inline void *OPENSSL_malloc(size_t s) { return malloc(s); }
static inline void OPENSSL_free(void *p) { free(p); }
static inline void *OPENSSL_zalloc(size_t s) {
  void *p = calloc(1, s);
  return p;
}
#ifdef __cplusplus
}
#endif
#else
#include_next <openssl/crypto.h>
#endif
