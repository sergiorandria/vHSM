#include <gtest/gtest.h>

#include "../../../src/crypto/rsa.h"

#include <openssl/evp.h>

TEST(RSA, GenerateSignVerify)
{
    // generate key
    RSAKeyPair kp = RSAUtil::generate_key(2048);
    ASSERT_NE(kp.key, nullptr);

    std::vector<uint8_t> msg = { 'h', 'e', 'l', 'l', 'o' };

    // sign
    std::vector<uint8_t> sig = RSAUtil::sign(kp.key, msg);
    ASSERT_FALSE(sig.empty());

    // verify
    bool ok = RSAUtil::verify(kp.key, msg, sig);
    EXPECT_TRUE(ok);

    EVP_PKEY_free(kp.key);
}
