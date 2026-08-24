#pragma once
#ifdef VHSM_OPENSSL_SHIM
#include "openssl/evp.h"
#ifdef __cplusplus
extern "C" {
#endif
#ifndef RSA_F4
#define RSA_F4 0x10001
#endif
static inline RSA *RSA_new() { return (RSA *)EVP_PKEY_new(); }
static inline void RSA_free(RSA *r) { EVP_PKEY_free((EVP_PKEY *)r); }
static inline int i2d_RSAPrivateKey(RSA *a, unsigned char **pp) {
  (void)a;
  (void)pp;
  return 0;
}
static inline RSA *d2i_RSAPrivateKey(RSA **a, const unsigned char **pp,
                                     long len) {
  (void)a;
  (void)pp;
  (void)len;
  return nullptr;
}
static inline int i2d_RSAPublicKey(RSA *a, unsigned char **pp) {
  (void)a;
  (void)pp;
  return 0;
}
static inline RSA *d2i_RSAPublicKey(RSA **a, const unsigned char **pp,
                                    long len) {
  (void)a;
  (void)pp;
  (void)len;
  return nullptr;
}
static inline int i2d_RSA_PUBKEY(RSA *a, unsigned char **pp) {
  (void)a;
  (void)pp;
  return 0;
}
static inline RSA *d2i_RSA_PUBKEY(RSA **a, const unsigned char **pp, long len) {
  (void)a;
  (void)pp;
  (void)len;
  return nullptr;
}
#ifdef __cplusplus
}
#endif
#else
#include_next <openssl/rsa.h>
#endif
