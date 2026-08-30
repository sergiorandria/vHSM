#include "fips.h"

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <openssl/evp.h>

#include "ecc.h"
#include "../metrics/metrics.h"

namespace vhsm::crypto {

bool fips_mode() {
  const char *v = std::getenv("VHSM_FIPS");
  if (!v)
    return false;
  std::string s(v);
  for (auto &c : s)
    c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
  return s == "1" || s == "true" || s == "yes" || s == "on";
}

bool mechanism_approved(unsigned long mech) {
  // FIPS-approved mechanisms: ECDSA (with SHA-2), RSA-PSS (with SHA-2),
  // raw SHA-2 digests, and AES (GCM/ECB/CBC) in approved key sizes.
  // RSA PKCS#1 v1.5 and SHA-1 are intentionally NOT approved.
  switch (mech) {
  case 0x00001041UL: // CKM_ECDSA
  case 0x00001047UL: // CKM_ECDSA_SHA256
  case 0x00001048UL: // CKM_ECDSA_SHA384
  case 0x00001049UL: // CKM_ECDSA_SHA512
  case 0x00000250UL: // CKM_SHA256
  case 0x00000251UL: // CKM_SHA384
  case 0x00000252UL: // CKM_SHA512
  case 0x0000000EUL: // CKM_SHA256_RSA_PKCS_PSS
  case 0x0000000FUL: // CKM_SHA384_RSA_PKCS_PSS
  case 0x00000010UL: // CKM_SHA512_RSA_PKCS_PSS
  case 0x00001087UL: // CKM_AES_GCM
  case 0x00001085UL: // CKM_AES_ECB
  case 0x00001086UL: // CKM_AES_CBC
    return true;
  default:
    return false;
  }
}

namespace {

bool sha256_kat() {
  const unsigned char in[] = "abc";
  unsigned char out[32];
  unsigned int len = 0;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
    return false;
  bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
            EVP_DigestUpdate(ctx, in, sizeof(in) - 1) == 1 &&
            EVP_DigestFinal_ex(ctx, out, &len) == 1;
  EVP_MD_CTX_free(ctx);
  if (!ok)
    return false;
  static const unsigned char expected[32] = {
      0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
      0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
      0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
  return std::memcmp(out, expected, 32) == 0;
}

bool aes_gcm_kat() {
  static const unsigned char key[32] = {0};
  static const unsigned char iv[12] = {0};
  static const unsigned char pt[16] = {0};
  unsigned char ct[16], tag[16], dec[16];
  int len = 0, tlen = 0;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return false;
  bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) == 1 &&
            EVP_EncryptUpdate(ctx, ct, &len, pt, sizeof(pt)) == 1 &&
            EVP_EncryptFinal_ex(ctx, ct + len, &len) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
  EVP_CIPHER_CTX_free(ctx);
  if (!ok)
    return false;
  ctx = EVP_CIPHER_CTX_new();
  ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) == 1 &&
       EVP_DecryptUpdate(ctx, dec, &len, ct, sizeof(ct)) == 1 &&
       EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) == 1 &&
       EVP_DecryptFinal_ex(ctx, dec + len, &tlen) == 1;
  EVP_CIPHER_CTX_free(ctx);
  return ok && std::memcmp(dec, pt, sizeof(pt)) == 0;
}

bool ecdsa_kat() {
  // P-256 sign/verify KAT using the project's ECC wrapper (no deprecated
  // OpenSSL EC_KEY/ECDSA API).
  using vhsm::crypto::Curve;
  using vhsm::crypto::ECC;
  auto kp = ECC::generate_key(Curve::EccCurveType_P256);
  bool ok = false;
  try {
    std::vector<uint8_t> digest(32, 1);
    auto sig = ECC::sign(kp, digest);
    ok = ECC::verify(kp, digest, sig);
  } catch (...) {
    ok = false;
  }
  ecc_free_key(kp);
  return ok;
}

} // namespace

bool fips_self_test() {
  bool ok = sha256_kat() && aes_gcm_kat() && ecdsa_kat();
  metrics::Metrics::instance().set(metrics::names::fips_active,
                                   fips_mode() ? 1 : 0);
  return ok;
}

} // namespace vhsm::crypto
