#include <gtest/gtest.h>
#include "../../../src/crypto/ecc.h"

using namespace vhsm::crypto;

TEST(ECC, GenerateSignVerifyDerive)
{
    ECKeyPair a = ECC::generate_key(Curve::P256);
    ECKeyPair b = ECC::generate_key(Curve::P256);

    ASSERT_NE(a.key, nullptr);
    ASSERT_NE(b.key, nullptr);

    std::vector<uint8_t> msg = { 'd','a','t','a' };

    std::vector<uint8_t> sig = ECC::sign(a.key, msg);
    ASSERT_FALSE(sig.empty());

    bool ok = ECC::verify(a.key, msg, sig);
    EXPECT_TRUE(ok);

    std::vector<uint8_t> secret = ECC::derive_shared_secret(a.key, b.key);
    ASSERT_FALSE(secret.empty());

    EVP_PKEY_free(a.key);
    EVP_PKEY_free(b.key);
}
