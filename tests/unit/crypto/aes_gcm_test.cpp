#include <gtest/gtest.h>
#include "../../../src/crypto/aes_gcm.h"

#include <openssl/rand.h>

using namespace vhsm::crypto;

TEST(AESGCM, EncryptDecrypt)
{
    std::vector<uint8_t> key(32);
    int rc = RAND_bytes(key.data(), key.size());
    ASSERT_EQ(rc, 1);

    std::vector<uint8_t> pt = { 't','e','s','t' };

    AESGCMResult res = AESGCM::encrypt(key, pt);
    ASSERT_FALSE(res.ciphertext.empty());
    ASSERT_EQ(res.nonce.size(), 12);
    ASSERT_EQ(res.tag.size(), 16);

    std::vector<uint8_t> out = AESGCM::decrypt(key, res);
    EXPECT_EQ(out, pt);
}
