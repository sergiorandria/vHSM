#pragma once
#ifdef VHSM_OPENSSL_SHIM
typedef void X509;
typedef void X509_NAME;
static inline X509 *d2i_X509(X509 **a, const unsigned char **pp, long len) {
  (void)a;
  (void)pp;
  (void)len;
  return nullptr;
}
static inline int i2d_X509(X509 *a, unsigned char **pp) {
  (void)a;
  (void)pp;
  return 0;
}
#else
#include_next <openssl/x509.h>
#endif
