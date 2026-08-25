#include "../../../src/crypto/ecc.h"
#include <gtest/gtest.h>

using namespace vhsm::crypto;

TEST(ECC, GenerateSignVerifyDerive) {
  ECCKeyPair a = ECC::generate_key(Curve::EccCurveType_P256);
  ECCKeyPair b = ECC::generate_key(Curve::EccCurveType_P256);

  ASSERT_NE(a.key, nullptr);
  ASSERT_NE(b.key, nullptr);

  std::vector<uint8_t> msg = {'d', 'a', 't', 'a'};

  std::vector<uint8_t> sig = ECC::sign(a, msg);
  ASSERT_FALSE(sig.empty());

  bool ok = ECC::verify(a, msg, sig);
  EXPECT_TRUE(ok);

  std::vector<uint8_t> secret = ECC::derive_shared_secret(a, b);
  ASSERT_FALSE(secret.empty());

  ecc_free_key(a);
  ecc_free_key(b);
}
