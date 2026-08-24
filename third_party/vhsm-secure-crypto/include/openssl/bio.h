#pragma once
#ifdef VHSM_OPENSSL_SHIM
#include "openssl/buffer.h"
#include "openssl/evp.h"
#include <vector>
struct bio_st {
  std::vector<unsigned char> data;
};
typedef struct bio_st BIO;
struct bio_method_st {
  int dummy = 0;
};
typedef struct bio_method_st BIO_METHOD;
inline const BIO_METHOD *BIO_s_mem() {
  static BIO_METHOD m;
  return &m;
}
inline BIO *BIO_new(const BIO_METHOD *m) {
  (void)m;
  return new BIO();
}
inline void BIO_free(BIO *b) { delete b; }
inline int BIO_get_mem_ptr(BIO *b, BUF_MEM **pp) {
  if (!b || !pp)
    return 0;
  BUF_MEM *m = new BUF_MEM();
  m->length = b->data.size();
  m->data = (char *)malloc(m->length ? m->length : 1);
  if (b->data.size())
    memcpy(m->data, b->data.data(), b->data.size());
  *pp = m;
  return 1;
}
inline BIO *BIO_new_mem_buf(const void *buf, int len) {
  (void)buf;
  (void)len;
  return new BIO();
}
inline int BIO_read(BIO *b, void *data, int len) {
  (void)b;
  (void)data;
  (void)len;
  return 0;
}
inline int i2d_PUBKEY_bio(BIO *bio, EVP_PKEY *pkey) {
  if (!bio || !pkey)
    return 0;
  std::string s;
  if (pkey->type == EVP_PKEY_RSA)
    s = "RSA-" + std::to_string(pkey->bits) + "-pub";
  else if (pkey->type == EVP_PKEY_EC)
    s = "EC-pub";
  else
    s = "UNKNOWN";
  bio->data.assign(s.begin(), s.end());
  return 1;
}
#else
#include_next <openssl/bio.h>
#endif
