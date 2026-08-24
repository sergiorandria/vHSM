#pragma once
#ifdef VHSM_OPENSSL_SHIM
#include "openssl/evp.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef void EC_GROUP;
typedef void EC_POINT;
#define POINT_CONVERSION_UNCOMPRESSED 4
static inline EC_KEY *EC_KEY_new() { return (EC_KEY *)EVP_PKEY_new(); }
static inline void EC_KEY_free(EC_KEY *k) { EVP_PKEY_free((EVP_PKEY *)k); }
static inline void EC_KEY_set_group(EC_KEY *k, EC_GROUP *g) {
  (void)k;
  (void)g;
}
static inline const EC_GROUP *EC_KEY_get0_group(const EC_KEY *k) {
  (void)k;
  return nullptr;
}
static inline const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *k) {
  (void)k;
  return nullptr;
}
static inline int EC_KEY_set_public_key(EC_KEY *k, EC_POINT *p) {
  (void)k;
  (void)p;
  return 1;
}
static inline EC_GROUP *EC_GROUP_new_by_curve_name(int nid) {
  (void)nid;
  return nullptr;
}
static inline void EC_GROUP_free(EC_GROUP *g) { (void)g; }
static inline EC_POINT *EC_POINT_new(const EC_GROUP *g) {
  (void)g;
  return nullptr;
}
static inline void EC_POINT_free(EC_POINT *p) { (void)p; }
static inline int EC_POINT_point2oct(const EC_GROUP *g, const EC_POINT *p,
                                     int form, unsigned char *buf, size_t len,
                                     void *ctx) {
  (void)g;
  (void)p;
  (void)form;
  (void)buf;
  (void)len;
  (void)ctx;
  return 0;
}
static inline int EC_POINT_oct2point(const EC_GROUP *g, EC_POINT *p,
                                     const unsigned char *buf, size_t len,
                                     void *ctx) {
  (void)g;
  (void)p;
  (void)buf;
  (void)len;
  (void)ctx;
  return 0;
}
static inline int i2d_ECPrivateKey(EC_KEY *k, unsigned char **pp) {
  (void)k;
  (void)pp;
  return 0;
}
static inline EC_KEY *d2i_ECPrivateKey(EC_KEY **a, const unsigned char **pp,
                                       long len) {
  (void)a;
  (void)pp;
  (void)len;
  return nullptr;
}
static inline int i2o_ECPublicKey(EC_KEY *k, unsigned char **pp) {
  (void)k;
  (void)pp;
  return 0;
}
static inline EC_KEY *d2i_EC_PUBKEY(EC_KEY **a, const unsigned char **pp,
                                    long len) {
  (void)a;
  (void)pp;
  (void)len;
  return nullptr;
}
static inline int i2d_ECPKParameters(const EC_GROUP *g, unsigned char **pp) {
  (void)g;
  (void)pp;
  return 0;
}
static inline EC_GROUP *d2i_ECPKParameters(EC_GROUP **a,
                                           const unsigned char **pp, long len) {
  (void)a;
  (void)pp;
  (void)len;
  return nullptr;
}
static inline EC_GROUP *EC_GROUP_new_from_params(int nid) {
  (void)nid;
  return nullptr;
}
#ifdef __cplusplus
}
#endif
#else
#include_next <openssl/ec.h>
#endif
