#include <gtest/gtest.h>

#include "../../../src/keystore/key_wrap.h"

using namespace vhsm::keystore;

TEST(KeyWrap, WrapThenUnwrapReturnsOriginal) {
    // 256-bit KEK (32 bytes)
    std::vector<u8> kek(32, 0x00); // all zeros for simplicity
    // In real test, we should use non-zero, but zero is fine for the algorithm.

    KeyWrap kw(kek);

    // Plaintext key must be multiple of 8 bytes and at least 16 bytes
    std::vector<u8> plaintext = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    std::vector<u8> ciphertext = kw.wrap(plaintext);
    // Ciphertext should be plaintext + 8 bytes (RFC 3394)
    EXPECT_EQ(ciphertext.size(), plaintext.size() + 8);

    std::vector<u8> decrypted = kw.unwrap(ciphertext);
    EXPECT_EQ(decrypted, plaintext);
}

TEST(KeyWrap, WrapRejectsInvalidPlaintextSize) {
    std::vector<u8> kek(32, 0x00);
    KeyWrap kw(kek);

    // Too short: 1 byte
    std::vector<u8> tooShort = {0x01};
    EXPECT_THROW(kw.wrap(tooShort), std::runtime_error);

    // Not multiple of 8: 15 bytes
    std::vector<u8> notMultiple8(15, 0x00);
    EXPECT_THROW(kw.wrap(notMultiple8), std::runtime_error);
}

TEST(KeyWrap, UnwrapRejectsInvalidCiphertextSize) {
    std::vector<u8> kek(32, 0x00);
    KeyWrap kw(kek);

    // Ciphertext must be at least 16 bytes (since plaintext min 16 bytes => ciphertext min 24 bytes)
    std::vector<u8> tooShort(10, 0x00);
    EXPECT_THROW(kw.unwrap(tooShort), std::runtime_error);

    // Not multiple of 8: 23 bytes
    std::vector<u8> notMultiple8(23, 0x00);
    EXPECT_THROW(kw.unwrap(notMultiple8), std::runtime_error);
}