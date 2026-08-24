#pragma once
#ifdef VHSM_OPENSSL_SHIM
#ifdef __cplusplus
extern "C" {
#endif
static inline void ERR_clear_error(void) {}
static inline unsigned long ERR_get_error(void) { return 0; }
static inline const char *ERR_error_string(unsigned long e, char *buf) {
  (void)e;
  if (buf)
    buf[0] = 0;
  return buf ? buf : "";
}
#ifdef __cplusplus
}
#endif
#else
#include_next <openssl/err.h>
#endif
