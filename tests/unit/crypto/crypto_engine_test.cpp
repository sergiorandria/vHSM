#include <gtest/gtest.h>

#include "../../../src/crypto/crypto_engine.h"
#include "../../../src/crypto/ecc.h"
#include "../../../src/crypto/rsa.h"

using namespace vhsm::crypto;

namespace {

// SHA-256 hex of "data" (lowercase), used to validate CryptoEngine digest.
const char *kData = "data";
const std::vector<u8> kMsg{kData, kData + 4};

} // namespace

// Native algorithm is chosen when no mechanism is requested.
TEST(CryptoEngine, PicksNativeAlgorithmForEcKey) {
  ECCKeyPair key = ECC::generate_key(Curve::EccCurveType_P256);
  SignResult r = CryptoEngine::sign(key, kMsg);
  EXPECT_EQ(r.mechanism_str, "CKM_ECDSA_SHA256");
  EXPECT_TRUE(ECC::verify(key, kMsg, r.signature));
  ecc_free_key(key);
}

TEST(CryptoEngine, PicksNativeAlgorithmForRsaKey) {
  RSAKeyPair key = RSAUtil::generate_key(2048);
  SignResult r = CryptoEngine::sign(key, kMsg);
  EXPECT_EQ(r.mechanism_str, "CKM_SHA256_RSA_PKCS");
  EXPECT_TRUE(RSAUtil::verify(key, kMsg, r.signature));
  rsa_free_key(key);
}

// Requested family matching the key type is honored.
TEST(CryptoEngine, HonorsMatchingMechanism) {
  ECCKeyPair key = ECC::generate_key(Curve::EccCurveType_P256);
  SignResult r = CryptoEngine::sign(key, kMsg, "CKM_ECDSA_SHA256");
  EXPECT_EQ(r.mechanism_str, "CKM_ECDSA_SHA256");
  EXPECT_TRUE(ECC::verify(key, kMsg, r.signature));
  ecc_free_key(key);
}

// PKCS#11 conformance (P0-4): a mechanism that conflicts with the key family
// must be REJECTED with CKR_KEY_TYPE_INCONSISTENT, not silently substituted.
TEST(CryptoEngine, MismatchRejectedByDefault) {
  ECCKeyPair ec = ECC::generate_key(Curve::EccCurveType_P256);
  EXPECT_THROW(CryptoEngine::sign(ec, kMsg, "CKM_SHA256_RSA_PKCS"),
               std::runtime_error);
  ecc_free_key(ec);

  RSAKeyPair rsa = RSAUtil::generate_key(2048);
  EXPECT_THROW(CryptoEngine::sign(rsa, kMsg, "CKM_ECDSA_SHA256"),
               std::runtime_error);
  rsa_free_key(rsa);
}

// The rejection message carries the PKCS#11 code so callers can map it.
TEST(CryptoEngine, MismatchMessageCarriesCkrCode) {
  ECCKeyPair ec = ECC::generate_key(Curve::EccCurveType_P256);
  try {
    (void)CryptoEngine::sign(ec, kMsg, "CKM_SHA256_RSA_PKCS");
    FAIL() << "expected throw";
  } catch (const std::runtime_error &e) {
    EXPECT_NE(std::string(e.what()).find("CKR_KEY_TYPE_INCONSISTENT"),
              std::string::npos);
  }
  ecc_free_key(ec);
}

// Explicit opt-in keeps legacy behavior; mechanism_str records the algorithm
// ACTUALLY used (native EC), never the requested-but-conflicting one.
TEST(CryptoEngine, FallsBackOnlyWithExplicitOptIn) {
  ECCKeyPair key = ECC::generate_key(Curve::EccCurveType_P256);
  SignResult r = CryptoEngine::sign(
      key, kMsg, "CKM_SHA256_RSA_PKCS",
      MechanismPolicy::AllowNativeFallback);
  EXPECT_EQ(r.mechanism_str, "CKM_ECDSA_SHA256")
      << "mechanism_str must reflect the algorithm actually used";
  EXPECT_TRUE(ECC::verify(key, kMsg, r.signature));
  ecc_free_key(key);

  RSAKeyPair rsa = RSAUtil::generate_key(2048);
  SignResult r2 = CryptoEngine::sign(rsa, kMsg, "CKM_ECDSA_SHA256",
                                     MechanismPolicy::AllowNativeFallback);
  EXPECT_EQ(r2.mechanism_str, "CKM_SHA256_RSA_PKCS");
  EXPECT_TRUE(RSAUtil::verify(rsa, kMsg, r2.signature));
  rsa_free_key(rsa);
}

// Digest and metadata are populated for auditability.
TEST(CryptoEngine, PopulatesDigestAndMetadata) {
  RSAKeyPair key = RSAUtil::generate_key(2048);
  SignResult r = CryptoEngine::sign(key, kMsg);
  EXPECT_EQ(r.digest_alg, "SHA-256");
  EXPECT_EQ(r.payload_size, static_cast<int>(kMsg.size()));
  EXPECT_FALSE(r.payload_digest.empty());
  EXPECT_EQ(r.payload_digest.size(), 64u); // 32-byte SHA-256 as hex
  rsa_free_key(key);
}
