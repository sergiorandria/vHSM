#include "vhsm/scrypto/rsa.h"
#include <stdexcept>

#if VHSM_SCRYPTO_HAS_OPENSSL
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#endif

namespace vhsm::scrypto {

void rsa_free(RsaKeyPair kp) noexcept {
#if VHSM_SCRYPTO_HAS_OPENSSL
  if (kp.handle)
    EVP_PKEY_free((EVP_PKEY *)kp.handle);
#else
  (void)kp;
#endif
}

RsaKeyPair rsa_generate(int bits) {
  if (bits != 2048 && bits != 3072 && bits != 4096)
    throw std::invalid_argument("RSA bits must be 2048/3072/4096");
#if VHSM_SCRYPTO_HAS_OPENSSL
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  if (!ctx)
    throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
  if (EVP_PKEY_keygen_init(ctx) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("keygen_init failed");
  }
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("set_bits failed");
  }
  EVP_PKEY *pkey = nullptr;
  if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("keygen failed");
  }
  EVP_PKEY_CTX_free(ctx);
  return {pkey, bits};
#else
  throw std::runtime_error("pure mode: RSA generate not implemented — enable "
                           "OpenSSL backend or provide bignum");
#endif
}

std::vector<uint8_t> rsa_sign(const RsaKeyPair &key,
                              const std::vector<uint8_t> &data, RsaPadding pad,
                              const std::string &hash) {
#if VHSM_SCRYPTO_HAS_OPENSSL
  if (!key.handle)
    throw std::invalid_argument("rsa_sign: null key");
  EVP_PKEY *pkey = (EVP_PKEY *)key.handle;
  // enforce policy: no raw sign with insecure hash
  if (hash != "SHA256" && hash != "SHA384" && hash != "SHA512")
    throw std::invalid_argument("unsupported hash");
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
    throw std::runtime_error("MD_CTX_new failed");
  const EVP_MD *md = EVP_get_digestbyname(hash.c_str());
  if (!md)
    md = EVP_sha256();
  int rc = 0;
  if (pad == RsaPadding::PSS) {
    rc = EVP_DigestSignInit(ctx, nullptr, md, nullptr, pkey);
    if (rc == 1) {
      EVP_PKEY_CTX *pctx = EVP_MD_CTX_get_pkey_ctx(ctx);
      EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
      EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST);
      EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md);
    }
  } else {
    rc = EVP_DigestSignInit(ctx, nullptr, md, nullptr, pkey);
  }
  if (rc != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("DigestSignInit failed");
  }
  size_t l = 0;
  if (EVP_DigestSign(ctx, nullptr, &l, data.data(), data.size()) != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("DigestSign len failed");
  }
  std::vector<uint8_t> sig(l);
  if (EVP_DigestSign(ctx, sig.data(), &l, data.data(), data.size()) != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("DigestSign failed");
  }
  sig.resize(l);
  EVP_MD_CTX_free(ctx);
  return sig;
#else
  (void)key;
  (void)data;
  (void)pad;
  (void)hash;
  throw std::runtime_error("pure RSA not implemented");
#endif
}
bool rsa_verify(const RsaKeyPair &key, const std::vector<uint8_t> &data,
                const std::vector<uint8_t> &sig, RsaPadding pad,
                const std::string &hash) {
#if VHSM_SCRYPTO_HAS_OPENSSL
  if (!key.handle)
    throw std::invalid_argument("rsa_verify: null key");
  EVP_PKEY *pkey = (EVP_PKEY *)key.handle;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  const EVP_MD *md = EVP_get_digestbyname(hash.c_str());
  if (!md)
    md = EVP_sha256();
  int rc = EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, pkey);
  if (rc == 1 && pad == RsaPadding::PSS) {
    EVP_PKEY_CTX *pctx = EVP_MD_CTX_get_pkey_ctx(ctx);
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST);
    EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md);
  }
  if (rc != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("VerifyInit failed");
  }
  int vr =
      EVP_DigestVerify(ctx, sig.data(), sig.size(), data.data(), data.size());
  EVP_MD_CTX_free(ctx);
  if (vr == 1)
    return true;
  if (vr == 0)
    return false;
  throw std::runtime_error("EVP_DigestVerify error");
#else
  (void)key;
  (void)data;
  (void)sig;
  (void)pad;
  (void)hash;
  throw std::runtime_error("pure not impl");
#endif
}
std::vector<uint8_t> rsa_encrypt(const RsaKeyPair &key,
                                 const std::vector<uint8_t> &pt,
                                 RsaPadding pad) {
#if VHSM_SCRYPTO_HAS_OPENSSL
  if (!key.handle)
    throw std::invalid_argument("null");
  if (pad != RsaPadding::OAEP_SHA256)
    throw std::invalid_argument(
        "only OAEP_SHA256 allowed for encrypt (hardened)");
  EVP_PKEY *pkey = (EVP_PKEY *)key.handle;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
  if (!ctx)
    throw std::runtime_error("CTX_new failed");
  if (EVP_PKEY_encrypt_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("encrypt_init");
  }
  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
  EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
  EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
  size_t outlen = 0;
  if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, pt.data(), pt.size()) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("encrypt len");
  }
  std::vector<uint8_t> out(outlen);
  if (EVP_PKEY_encrypt(ctx, out.data(), &outlen, pt.data(), pt.size()) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("encrypt");
  }
  out.resize(outlen);
  EVP_PKEY_CTX_free(ctx);
  return out;
#else
  (void)key;
  (void)pt;
  (void)pad;
  throw std::runtime_error("pure not impl");
#endif
}
std::vector<uint8_t> rsa_decrypt(const RsaKeyPair &key,
                                 const std::vector<uint8_t> &ct,
                                 RsaPadding pad) {
#if VHSM_SCRYPTO_HAS_OPENSSL
  if (!key.handle)
    throw std::invalid_argument("null");
  if (pad != RsaPadding::OAEP_SHA256)
    throw std::invalid_argument("only OAEP_SHA256 allowed");
  EVP_PKEY *pkey = (EVP_PKEY *)key.handle;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
  if (!ctx)
    throw std::runtime_error("CTX_new");
  if (EVP_PKEY_decrypt_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("decrypt_init");
  }
  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
  EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
  EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
  size_t outlen = 0;
  if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, ct.data(), ct.size()) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("decrypt len");
  }
  std::vector<uint8_t> out(outlen);
  if (EVP_PKEY_decrypt(ctx, out.data(), &outlen, ct.data(), ct.size()) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("decrypt failed — auth?");
  }
  out.resize(outlen);
  EVP_PKEY_CTX_free(ctx);
  return out;
#else
  (void)key;
  (void)ct;
  (void)pad;
  throw std::runtime_error("pure not impl");
#endif
}
void *rsa_handle_from_evp(void *evp) noexcept { return evp; }
void *evp_from_rsa_handle(void *h) noexcept { return h; }

} // namespace vhsm::scrypto
