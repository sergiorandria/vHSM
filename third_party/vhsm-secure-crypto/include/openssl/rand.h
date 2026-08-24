#pragma once
#ifdef VHSM_OPENSSL_SHIM
#include <stddef.h>
#ifdef __cplusplus
#include "vhsm/scrypto/rng.h"
inline int RAND_bytes(unsigned char *buf, int num) {
  try {
    vhsm::scrypto::SecureRng rng;
    rng.bytes(buf, (size_t)num);
    return 1;
  } catch (...) {
    return 0;
  }
}
#else
int RAND_bytes(unsigned char *buf, int num);
#endif
#else
#include_next <openssl/rand.h>
#endif
