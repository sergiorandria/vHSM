#include "vhsm/scrypto/ec.h"
#include <stdexcept>
#if VHSM_SCRYPTO_HAS_OPENSSL
#include <openssl/ec.h>
#include <openssl/evp.h>
#endif

namespace vhsm::scrypto {

void ec_free(EcKeyPair kp) noexcept {
#if VHSM_SCRYPTO_HAS_OPENSSL
  if (kp.handle)
    EVP_PKEY_free((EVP_PKEY *)kp.handle);
#endif
}
EcKeyPair ec_generate(Curve c) {
#if VHSM_SCRYPTO_HAS_OPENSSL
  int nid = 0;
  switch (c) {
  case Curve::P256:
    nid = NID_X9_62_prime256v1;
    break;
  case Curve::P384:
    nid = NID_secp384r1;
    break;
  case Curve::P521:
    nid = NID_secp521r1;
    break;
  }
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  if (!ctx)
    throw std::runtime_error("EC ctx new failed");
  if (EVP_PKEY_keygen_init(ctx) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("keygen_init");
  }
  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("set_curve");
  }
  EVP_PKEY *pkey = nullptr;
  if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("keygen");
  }
  EVP_PKEY_CTX_free(ctx);
  return {pkey, c};
#else
  (void)c;
  throw std::runtime_error("pure EC not implemented");
#endif
}
std::vector<uint8_t> ec_sign(const EcKeyPair &kp,
                             const std::vector<uint8_t> &d) {
#if VHSM_SCRYPTO_HAS_OPENSSL
  if (!kp.handle)
    throw std::invalid_argument("null");
  EVP_PKEY *pkey = (EVP_PKEY *)kp.handle;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("sign init");
  }
  size_t l = 0;
  if (EVP_DigestSign(ctx, nullptr, &l, d.data(), d.size()) != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("sign len");
  }
  std::vector<uint8_t> s(l);
  if (EVP_DigestSign(ctx, s.data(), &l, d.data(), d.size()) != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("sign");
  }
  s.resize(l);
  EVP_MD_CTX_free(ctx);
  return s;
#else
  (void)kp;
  (void)d;
  throw std::runtime_error("pure not impl");
#endif
}
bool ec_verify(const EcKeyPair &kp, const std::vector<uint8_t> &d,
               const std::vector<uint8_t> &sig) {
#if VHSM_SCRYPTO_HAS_OPENSSL
  EVP_PKEY *pkey = (EVP_PKEY *)kp.handle;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("verify init");
  }
  int rc = EVP_DigestVerify(ctx, sig.data(), sig.size(), d.data(), d.size());
  EVP_MD_CTX_free(ctx);
  if (rc == 1)
    return true;
  if (rc == 0)
    return false;
  throw std::runtime_error("verify error");
#else
  (void)kp;
  (void)d;
  (void)sig;
  throw std::runtime_error("pure not impl");
#endif
}
std::vector<uint8_t> ecdh_derive(const EcKeyPair &priv, const EcKeyPair &peer) {
#if VHSM_SCRYPTO_HAS_OPENSSL
  EVP_PKEY *a = (EVP_PKEY *)priv.handle;
  EVP_PKEY *b = (EVP_PKEY *)peer.handle;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(a, nullptr);
  if (!ctx)
    throw std::runtime_error("derive ctx");
  if (EVP_PKEY_derive_init(ctx) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("derive init");
  }
  if (EVP_PKEY_derive_set_peer(ctx, b) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("set_peer");
  }
  size_t l = 0;
  if (EVP_PKEY_derive(ctx, nullptr, &l) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("derive len");
  }
  std::vector<uint8_t> s(l);
  if (EVP_PKEY_derive(ctx, s.data(), &l) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("derive");
  }
  s.resize(l);
  EVP_PKEY_CTX_free(ctx);
  return s;
#else
  (void)priv;
  (void)peer;
  throw std::runtime_error("pure not impl");
#endif
}
void *ec_handle_from_evp(void *e) noexcept { return e; }

} // namespace vhsm::scrypto
