#include <gtest/gtest.h>

#include "../../../src/crypto/rsa.h"

using namespace vhsm::crypto;

TEST(RSA, GenerateSignVerify) {
  // generate key
  RSAKeyPair kp = RSAUtil::generate_key(2048);
  ASSERT_NE(kp.key, nullptr);

  std::vector<uint8_t> msg = {'h', 'e', 'l', 'l', 'o'};

  // sign
  std::vector<uint8_t> sig = RSAUtil::sign(kp, msg);
  ASSERT_FALSE(sig.empty());

  // verify
  bool ok = RSAUtil::verify(kp, msg, sig);
  EXPECT_TRUE(ok);

  rsa_free_key(kp);
}
