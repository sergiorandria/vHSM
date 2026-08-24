#pragma once
#ifdef VHSM_OPENSSL_SHIM
// Shim: openssl/evp.h -> vhsm scrypto (OpenSSL-free build)
#include <cctype>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef __cplusplus
#include "openssl/crypto.h"
#include "vhsm/scrypto/aes.h"
#include "vhsm/scrypto/aes_gcm.h"
#include "vhsm/scrypto/ec.h"
#include "vhsm/scrypto/hash.h"
#include "vhsm/scrypto/hmac.h"
#include "vhsm/scrypto/mem.h"
#include "vhsm/scrypto/rsa.h"
#include <string>
#include <vector>
struct evp_pkey_st {
  int type = 0;
  void *handle = nullptr;
  int bits = 0;
};
struct evp_pkey_ctx_st {
  int pkey_type = 0;
  int rsa_bits = 2048;
  int ec_nid = 0;
  int padding = 1;
  const void *md = nullptr;
  const void *mgf1_md = nullptr;
  int saltlen = -1;
  std::vector<unsigned char> oaep_label;
  std::string oaep_md_name;
  evp_pkey_st *pkey = nullptr;
  evp_pkey_st *peer = nullptr;
};
struct evp_md_ctx_st {
  int is_sign = 0;
  int is_verify = 0;
  evp_pkey_st *pkey = nullptr;
  const void *md = nullptr;
  std::vector<unsigned char> data;
};
struct evp_cipher_ctx_st {
  std::vector<unsigned char> key;
  std::vector<unsigned char> iv;
  int enc = 1;
  int tag_set = 0;
  unsigned char tag[16]{};
  std::vector<unsigned char> buf;
};
struct evp_mac_ctx_st {
  int dummy = 0;
};
struct evp_md_st {
  const char *name;
  int size;
};
struct evp_cipher_st {
  const char *name;
  int keylen;
  int ivlen;
};
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_mac_ctx_st EVP_MAC_CTX;
typedef struct evp_md_st EVP_MD;
typedef struct evp_cipher_st EVP_CIPHER;
typedef EVP_PKEY RSA;
typedef EVP_PKEY EC_KEY;
#define EVP_PKEY_RSA 6
#define EVP_PKEY_EC 408
#define EVP_PKEY_RSA_PSS 912
#define NID_X9_62_prime256v1 415
#define NID_secp384r1 715
#define NID_secp521r1 716
#define RSA_PKCS1_PADDING 1
#define RSA_NO_PADDING 3
#define RSA_PKCS1_OAEP_PADDING 4
#define RSA_PKCS1_PSS_PADDING 6
#define RSA_PSS_SALTLEN_DIGEST -1
#define EVP_CTRL_GCM_SET_IVLEN 0x9
#define EVP_CTRL_GCM_GET_TAG 0x10
#define EVP_CTRL_GCM_SET_TAG 0x11
static EVP_MD kSha256Md{"SHA256", 32};
static EVP_MD kSha384Md{"SHA384", 48};
static EVP_MD kSha512Md{"SHA512", 64};
static EVP_MD kSha1Md{"SHA1", 20};
static EVP_CIPHER kAes256Gcm{"AES-256-GCM", 32, 12};
static EVP_CIPHER kAes192Gcm{"AES-192-GCM", 24, 12};
static EVP_CIPHER kAes128Gcm{"AES-128-GCM", 16, 12};
static EVP_CIPHER kAes256Ecb{"AES-256-ECB", 32, 0};
inline const EVP_MD *EVP_sha256() { return &kSha256Md; }
inline const EVP_MD *EVP_sha384() { return &kSha384Md; }
inline const EVP_MD *EVP_sha512() { return &kSha512Md; }
inline const EVP_MD *EVP_sha1() { return &kSha1Md; }
inline const EVP_MD *EVP_get_digestbyname(const char *name) {
  if (!name)
    return nullptr;
  std::string n(name);
  for (auto &c : n)
    c = (char)toupper((unsigned char)c);
  if (n == "SHA256" || n == "SHA-256")
    return &kSha256Md;
  if (n == "SHA384" || n == "SHA-384")
    return &kSha384Md;
  if (n == "SHA512" || n == "SHA-512")
    return &kSha512Md;
  if (n == "SHA1" || n == "SHA-1")
    return &kSha1Md;
  return &kSha256Md;
}
inline int EVP_MD_size(const EVP_MD *md) { return md ? md->size : 32; }
inline const EVP_CIPHER *EVP_aes_256_gcm() { return &kAes256Gcm; }
inline const EVP_CIPHER *EVP_aes_192_gcm() { return &kAes192Gcm; }
inline const EVP_CIPHER *EVP_aes_128_gcm() { return &kAes128Gcm; }
inline const EVP_CIPHER *EVP_aes_256_ecb() { return &kAes256Ecb; }
inline int EVP_PKEY_id(const EVP_PKEY *p) { return p ? p->type : -1; }
inline int EVP_PKEY_get_base_id(const EVP_PKEY *p) { return p ? p->type : -1; }
inline EVP_PKEY *EVP_PKEY_new() { return new EVP_PKEY(); }
inline void EVP_PKEY_free(EVP_PKEY *p) {
  if (p) {
    if (p->handle) {
      if (p->type == EVP_PKEY_RSA)
        vhsm::scrypto::rsa_free({p->handle, p->bits});
      else if (p->type == EVP_PKEY_EC)
        vhsm::scrypto::ec_free({p->handle, vhsm::scrypto::Curve::P256});
    }
    delete p;
  }
}
inline int EVP_PKEY_assign_RSA(EVP_PKEY *p, void *rsa) {
  if (!p)
    return 0;
  p->type = EVP_PKEY_RSA;
  p->handle = rsa;
  return 1;
}
inline int EVP_PKEY_assign_EC_KEY(EVP_PKEY *p, void *ec) {
  if (!p)
    return 0;
  p->type = EVP_PKEY_EC;
  p->handle = ec;
  return 1;
}
inline RSA *EVP_PKEY_get1_RSA(EVP_PKEY *p) {
  return (RSA *)((p && p->type == EVP_PKEY_RSA) ? p->handle : nullptr);
}
inline EC_KEY *EVP_PKEY_get1_EC_KEY(EVP_PKEY *p) {
  return (EC_KEY *)((p && p->type == EVP_PKEY_EC) ? p->handle : nullptr);
}
inline EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *p, void *e) {
  (void)e;
  auto *ctx = new EVP_PKEY_CTX();
  ctx->pkey = p;
  ctx->pkey_type = p ? p->type : 0;
  return ctx;
}
inline EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, void *e) {
  (void)e;
  auto *ctx = new EVP_PKEY_CTX();
  ctx->pkey_type = id;
  return ctx;
}
inline void EVP_PKEY_CTX_free(EVP_PKEY_CTX *c) { delete c; }
inline int EVP_PKEY_keygen_init(EVP_PKEY_CTX *c) { return c ? 1 : 0; }
inline int EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX *c, int bits) {
  if (c)
    c->rsa_bits = bits;
  return 1;
}
inline int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *c, int nid) {
  if (c)
    c->ec_nid = nid;
  return 1;
}
inline int EVP_PKEY_keygen(EVP_PKEY_CTX *c, EVP_PKEY **out) {
  if (!c || !out)
    return 0;
  try {
    if (c->pkey_type == EVP_PKEY_RSA) {
      auto kp = vhsm::scrypto::rsa_generate(c->rsa_bits);
      auto *p = new EVP_PKEY();
      p->type = EVP_PKEY_RSA;
      p->handle = kp.handle;
      p->bits = kp.bits;
      *out = p;
      return 1;
    }
    if (c->pkey_type == EVP_PKEY_EC) {
      vhsm::scrypto::Curve cv = vhsm::scrypto::Curve::P256;
      if (c->ec_nid == NID_secp384r1)
        cv = vhsm::scrypto::Curve::P384;
      else if (c->ec_nid == NID_secp521r1)
        cv = vhsm::scrypto::Curve::P521;
      auto kp = vhsm::scrypto::ec_generate(cv);
      auto *p = new EVP_PKEY();
      p->type = EVP_PKEY_EC;
      p->handle = kp.handle;
      p->bits = 0;
      *out = p;
      return 1;
    }
  } catch (...) {
    return 0;
  }
  return 0;
}
inline int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *c) { return c ? 1 : 0; }
inline int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *c) { return c ? 1 : 0; }
inline int EVP_PKEY_sign_init(EVP_PKEY_CTX *c) { return c ? 1 : 0; }
inline int EVP_PKEY_verify_init(EVP_PKEY_CTX *c) { return c ? 1 : 0; }
inline int EVP_PKEY_derive_init(EVP_PKEY_CTX *c) { return c ? 1 : 0; }
inline int EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *c, int pad) {
  if (c)
    c->padding = pad;
  return 1;
}
inline int EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX *c, const EVP_MD *md) {
  if (c)
    c->oaep_md_name = md ? md->name : "";
  return 1;
}
inline int EVP_PKEY_CTX_set_rsa_mgf1_md(EVP_PKEY_CTX *c, const EVP_MD *md) {
  if (c)
    c->mgf1_md = md;
  return 1;
}
inline int EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX *c, int len) {
  if (c)
    c->saltlen = len;
  return 1;
}
inline int EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX *c, const EVP_MD *md) {
  if (c)
    c->md = md;
  return 1;
}
inline int EVP_PKEY_CTX_set0_rsa_oaep_label(EVP_PKEY_CTX *c,
                                            unsigned char *label, int len) {
  if (c && label && len > 0) {
    c->oaep_label.assign(label, label + len);
    free(label);
  } else if (label)
    free(label);
  return 1;
}
inline int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *c, EVP_PKEY *peer) {
  if (c)
    c->peer = peer;
  return 1;
}
inline int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out,
                            size_t *outlen, const unsigned char *in,
                            size_t inlen) {
  if (!ctx || !ctx->pkey || !outlen)
    return 0;
  try {
    auto *pkey = ctx->pkey;
    vhsm::scrypto::RsaKeyPair kp{pkey->handle, pkey->bits};
    auto pt = std::vector<unsigned char>(in, in + inlen);
    auto ct = vhsm::scrypto::rsa_encrypt(
        kp, pt, vhsm::scrypto::RsaPadding::OAEP_SHA256);
    if (!out) {
      *outlen = ct.size();
      return 1;
    }
    if (*outlen < ct.size())
      return 0;
    memcpy(out, ct.data(), ct.size());
    *outlen = ct.size();
    return 1;
  } catch (...) {
    return 0;
  }
}
inline int EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out,
                            size_t *outlen, const unsigned char *in,
                            size_t inlen) {
  if (!ctx || !ctx->pkey || !outlen)
    return 0;
  try {
    auto *pkey = ctx->pkey;
    vhsm::scrypto::RsaKeyPair kp{pkey->handle, pkey->bits};
    auto ct = std::vector<unsigned char>(in, in + inlen);
    auto pt = vhsm::scrypto::rsa_decrypt(
        kp, ct, vhsm::scrypto::RsaPadding::OAEP_SHA256);
    if (!out) {
      *outlen = pt.size();
      return 1;
    }
    if (*outlen < pt.size())
      return 0;
    memcpy(out, pt.data(), pt.size());
    *outlen = pt.size();
    return 1;
  } catch (...) {
    return 0;
  }
}
inline int EVP_PKEY_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                         const unsigned char *tbs, size_t tbslen) {
  if (!ctx || !ctx->pkey || !siglen)
    return 0;
  try {
    auto *pkey = ctx->pkey;
    auto data = std::vector<unsigned char>(tbs, tbs + tbslen);
    std::vector<unsigned char> out;
    if (pkey->type == EVP_PKEY_RSA) {
      vhsm::scrypto::RsaKeyPair kp{pkey->handle, pkey->bits};
      auto pad = (ctx->padding == RSA_PKCS1_PSS_PADDING)
                     ? vhsm::scrypto::RsaPadding::PSS
                     : vhsm::scrypto::RsaPadding::PKCS1;
      out = vhsm::scrypto::rsa_sign(kp, data, pad, "SHA256");
    } else {
      vhsm::scrypto::EcKeyPair kp{pkey->handle, vhsm::scrypto::Curve::P256};
      out = vhsm::scrypto::ec_sign(kp, data);
    }
    if (!sig) {
      *siglen = out.size();
      return 1;
    }
    if (*siglen < out.size())
      return 0;
    memcpy(sig, out.data(), out.size());
    *siglen = out.size();
    return 1;
  } catch (...) {
    return 0;
  }
}
inline int EVP_PKEY_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig,
                           size_t siglen, const unsigned char *tbs,
                           size_t tbslen) {
  if (!ctx || !ctx->pkey)
    return -1;
  try {
    auto *pkey = ctx->pkey;
    auto data = std::vector<unsigned char>(tbs, tbs + tbslen);
    auto s = std::vector<unsigned char>(sig, sig + siglen);
    bool ok = false;
    if (pkey->type == EVP_PKEY_RSA) {
      vhsm::scrypto::RsaKeyPair kp{pkey->handle, pkey->bits};
      auto pad = (ctx->padding == RSA_PKCS1_PSS_PADDING)
                     ? vhsm::scrypto::RsaPadding::PSS
                     : vhsm::scrypto::RsaPadding::PKCS1;
      ok = vhsm::scrypto::rsa_verify(kp, data, s, pad, "SHA256");
    } else {
      vhsm::scrypto::EcKeyPair kp{pkey->handle, vhsm::scrypto::Curve::P256};
      ok = vhsm::scrypto::ec_verify(kp, data, s);
    }
    return ok ? 1 : 0;
  } catch (...) {
    return -1;
  }
}
inline int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                           size_t *keylen) {
  if (!ctx || !ctx->pkey || !ctx->peer || !keylen)
    return 0;
  try {
    vhsm::scrypto::EcKeyPair priv{ctx->pkey->handle,
                                  vhsm::scrypto::Curve::P256};
    vhsm::scrypto::EcKeyPair peer{ctx->peer->handle,
                                  vhsm::scrypto::Curve::P256};
    auto sec = vhsm::scrypto::ecdh_derive(priv, peer);
    if (!key) {
      *keylen = sec.size();
      return 1;
    }
    if (*keylen < sec.size())
      return 0;
    memcpy(key, sec.data(), sec.size());
    *keylen = sec.size();
    return 1;
  } catch (...) {
    return 0;
  }
}
inline EVP_MD_CTX *EVP_MD_CTX_new() { return new EVP_MD_CTX(); }
inline void EVP_MD_CTX_free(EVP_MD_CTX *c) { delete c; }
inline int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *md, void *eng) {
  (void)eng;
  if (!ctx || !md)
    return 0;
  ctx->md = md;
  ctx->data.clear();
  return 1;
}
inline int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt) {
  if (!ctx)
    return 0;
  if (!d && cnt > 0)
    return 0;
  auto *p = (const unsigned char *)d;
  ctx->data.insert(ctx->data.end(), p, p + cnt);
  return 1;
}
inline int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md,
                              unsigned int *s) {
  if (!ctx || !md)
    return 0;
  const char *name = ctx->md ? ((const EVP_MD *)ctx->md)->name : "SHA256";
  std::vector<unsigned char> out;
  if (std::string(name) == "SHA512")
    out = vhsm::scrypto::hash(vhsm::scrypto::HashAlg::SHA512, ctx->data.data(),
                              ctx->data.size());
  else if (std::string(name) == "SHA384")
    out = vhsm::scrypto::hash(vhsm::scrypto::HashAlg::SHA384, ctx->data.data(),
                              ctx->data.size());
  else
    out = vhsm::scrypto::hash(vhsm::scrypto::HashAlg::SHA256, ctx->data.data(),
                              ctx->data.size());
  memcpy(md, out.data(), out.size());
  if (s)
    *s = (unsigned int)out.size();
  return 1;
}
inline int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                              const EVP_MD *md, void *e, EVP_PKEY *pkey) {
  (void)e;
  if (!ctx)
    return 0;
  ctx->is_sign = 1;
  ctx->pkey = pkey;
  ctx->md = md;
  ctx->data.clear();
  if (pctx)
    *pctx = (EVP_PKEY_CTX *)pkey;
  return 1;
}
inline int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                          const unsigned char *tbs, size_t tbslen) {
  if (!ctx || !siglen)
    return 0;
  auto data = std::vector<unsigned char>(tbs, tbs + tbslen);
  data.insert(data.end(), ctx->data.begin(), ctx->data.end());
  EVP_PKEY_CTX tmp;
  tmp.pkey = ctx->pkey;
  tmp.padding = RSA_PKCS1_PADDING;
  return EVP_PKEY_sign(&tmp, sig, siglen, data.data(), data.size());
}
inline int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                                const EVP_MD *md, void *e, EVP_PKEY *pkey) {
  (void)e;
  if (!ctx)
    return 0;
  ctx->is_verify = 1;
  ctx->pkey = pkey;
  ctx->md = md;
  if (pctx)
    *pctx = (EVP_PKEY_CTX *)pkey;
  return 1;
}
inline int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sig,
                            size_t siglen, const unsigned char *tbs,
                            size_t tbslen) {
  if (!ctx)
    return -1;
  auto data = std::vector<unsigned char>(tbs, tbs + tbslen);
  data.insert(data.end(), ctx->data.begin(), ctx->data.end());
  EVP_PKEY_CTX tmp;
  tmp.pkey = ctx->pkey;
  tmp.padding = RSA_PKCS1_PADDING;
  return EVP_PKEY_verify(&tmp, sig, siglen, data.data(), data.size());
}
inline EVP_PKEY_CTX *EVP_MD_CTX_get_pkey_ctx(EVP_MD_CTX *ctx) {
  return (EVP_PKEY_CTX *)ctx->pkey;
}
inline EVP_PKEY *d2i_PUBKEY(EVP_PKEY **a, const unsigned char **pp, long len) {
  (void)a;
  (void)pp;
  (void)len;
  return nullptr;
}
inline int i2d_PUBKEY(EVP_PKEY *a, unsigned char **pp) {
  (void)a;
  (void)pp;
  return 0;
}
inline EVP_CIPHER_CTX *EVP_CIPHER_CTX_new() { return new EVP_CIPHER_CTX(); }
inline void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *c) { delete c; }
inline int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad) {
  (void)c;
  (void)pad;
  return 1;
}
inline int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                              void *impl, const unsigned char *key,
                              const unsigned char *iv) {
  (void)impl;
  if (!ctx)
    return 0;
  if (cipher) {
    ctx->key.clear();
    ctx->iv.clear();
  }
  if (key) {
    ctx->key.assign(key, key + 32);
  }
  if (iv) {
    ctx->iv.assign(iv, iv + 12);
  }
  return 1;
}
inline int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                              void *impl, const unsigned char *key,
                              const unsigned char *iv) {
  return EVP_EncryptInit_ex(ctx, cipher, impl, key, iv);
}
inline int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                               void *ptr) {
  if (!ctx)
    return 0;
  if (type == EVP_CTRL_GCM_SET_IVLEN) {
    (void)arg;
    return 1;
  }
  if (type == EVP_CTRL_GCM_GET_TAG) {
    if (ptr && arg == 16)
      memcpy(ptr, ctx->tag, 16);
    return 1;
  }
  if (type == EVP_CTRL_GCM_SET_TAG) {
    if (ptr && arg == 16) {
      memcpy(ctx->tag, ptr, 16);
      ctx->tag_set = 1;
    }
    return 1;
  }
  return 1;
}
inline int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                             const unsigned char *in, int inl) {
  if (!ctx || !outl)
    return 0;
  if (inl == 0) {
    *outl = 0;
    return 1;
  }
  if (ctx->iv.empty()) {
    if (inl != 16)
      return 0;
    vhsm::scrypto::aes256_ecb_encrypt_block(ctx->key.data(), in, out);
    *outl = 16;
    return 1;
  }
  ctx->buf.assign(in, in + inl);
  *outl = 0;
  return 1;
}
inline int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                             const unsigned char *in, int inl) {
  return EVP_EncryptUpdate(ctx, out, outl, in, inl);
}
inline int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               int *outl) {
  (void)out;
  if (!ctx || !outl)
    return 0;
  if (!ctx->iv.empty()) {
    try {
      auto pt = ctx->buf;
      auto res = vhsm::scrypto::aes256_gcm_encrypt_with_nonce(ctx->key, ctx->iv,
                                                              pt, {});
      memcpy(ctx->tag, res.tag.data(), 16);
    } catch (...) {
    }
    *outl = 0;
    return 1;
  }
  *outl = 0;
  return 1;
}
inline int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               int *outl) {
  if (!ctx || !outl)
    return 0;
  if (ctx->iv.empty()) {
    *outl = 0;
    return 1;
  }
  try {
    auto res = vhsm::scrypto::GcmResult{
        ctx->buf, ctx->iv, std::vector<unsigned char>(ctx->tag, ctx->tag + 16)};
    auto pt = vhsm::scrypto::aes256_gcm_decrypt(ctx->key, res);
    if (!pt.empty() && out)
      memcpy(out, pt.data(), pt.size());
    *outl = (int)pt.size();
    return 1;
  } catch (...) {
    return 0;
  }
}
#endif
#else
#include_next <openssl/evp.h>
#endif
