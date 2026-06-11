// Key_fingerprint_test.cpp
// Unit tests for `Key_fingerprint` demonstrating fingerprint
// generation from different public-key inputs.
// - raw SPKI bytes
// - EC key pair
// - RSA key pair

#include <gtest/gtest.h>
#include <openssl/evp.h>
#include "../../../src/keystore/Key_fingerprint.h"
#include "../../../src/crypto/ecc.h"
#include "../../../src/crypto/rsa.h"

using namespace vhsm::crypto;

// Test 1: Raw SPKI input only
TEST(KeyFingerprintTest, FromRawSPKI)
{
    std::vector<uint8_t> spki = {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
        0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
        0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00,
    };

    Key_fingerprint kf;
    auto fingerprint = kf.from_SPKI(spki);

    bool all_zero = std::all_of(fingerprint.begin(), fingerprint.end(), [](uint8_t b) { return b == 0; });
    EXPECT_FALSE(all_zero);
}

// Test 2: EC key pair only
TEST(KeyFingerprintTest, FromECCKeyPair)
{
    Key_fingerprint kf;
    ECKeyPair ec_key = ECC::generate_key(Curve::P256);
    ASSERT_NE(ec_key.key, nullptr);
    
    auto ec_fingerprint = kf.from_public_key(ec_key);
    bool all_zero = std::all_of(ec_fingerprint.begin(), ec_fingerprint.end(), [](uint8_t b) { return b == 0; });
    EXPECT_FALSE(all_zero);
    
    EVP_PKEY_free(ec_key.key);
}

// Test 3: RSA key pair only
TEST(KeyFingerprintTest, FromRSAKeyPair)
{
    Key_fingerprint kf;
    RSAKeyPair rsa_key = RSAUtil::generate_key(2048);
    ASSERT_NE(rsa_key.key, nullptr);
    
    auto rsa_fingerprint = kf.from_public_key(rsa_key);
    bool all_zero = std::all_of(rsa_fingerprint.begin(), rsa_fingerprint.end(), [](uint8_t b) { return b == 0; });
    EXPECT_FALSE(all_zero);
    
    EVP_PKEY_free(rsa_key.key);
}