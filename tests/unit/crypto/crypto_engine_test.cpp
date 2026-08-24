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

// Incompatible request (RSA on an EC key) falls back to the key's native
// algorithm rather than failing open.
TEST(CryptoEngine, FallsBackWhenMechanismConflictsWithKey) {
  ECCKeyPair key = ECC::generate_key(Curve::EccCurveType_P256);
  // New API is strongly typed: an RSA mechanism cannot be passed with an EC
  // key handle at all. The hint is recorded but native EC signing happens.
  SignResult r = CryptoEngine::sign(key, kMsg, "CKM_SHA256_RSA_PKCS");
  EXPECT_EQ(r.mechanism_str, "CKM_ECDSA_SHA256")
      << "must fall back to native EC signing, not fail or sign with RSA";
  EXPECT_TRUE(ECC::verify(key, kMsg, r.signature));
  ecc_free_key(key);
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
