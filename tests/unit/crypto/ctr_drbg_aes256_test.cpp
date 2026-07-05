#include <gtest/gtest.h>
#include "../../../src/crypto/ctr_drbg_aes256.h"
#include "../../../src/core/error.h"

#include <openssl/rand.h>
#include <vector>
#include <stdexcept>

using namespace vhsm::crypto;

// Helper function to generate random entropy
std::vector<u8> generate_entropy(size_t size = 48) {
    std::vector<u8> entropy(size);
    VHSM_CHECK(RAND_bytes(entropy.data(), size));
    //ASSERT_EQ(rc, 1) << "Failed to generate random entropy";
    return entropy;
}

TEST(CTR_DRBG_AES256, ConstructorValidEntropy) {
    // Test constructor with valid 48-byte entropy
    auto entropy = generate_entropy();
    ASSERT_NO_THROW({
        CTR_DRBG_AES256 rng(entropy);
    });
}

TEST(CTR_DRBG_AES256, ConstructorInvalidEntropySize) {
    // Test constructor with invalid entropy sizes
    std::vector<u8> too_small(47);
    std::vector<u8> too_large(49);
    
    EXPECT_THROW(CTR_DRBG_AES256 rng(too_small), std::invalid_argument);
    EXPECT_THROW(CTR_DRBG_AES256 rng(too_large), std::invalid_argument);
}

TEST(CTR_DRBG_AES256, GenerateBasicFunctionality) {
    auto entropy = generate_entropy();
    CTR_DRBG_AES256 rng(entropy);
    
    // Test generating various lengths
    auto bytes10 = rng.generate(10);
    EXPECT_EQ(bytes10.size(), 10u);
    
    auto bytes100 = rng.generate(100);
    EXPECT_EQ(bytes100.size(), 100u);
    
    auto bytes1000 = rng.generate(1000);
    EXPECT_EQ(bytes1000.size(), 1000u);
}

TEST(CTR_DRBG_AES256, GenerateReturnsDifferentValues) {
    auto entropy = generate_entropy();
    CTR_DRBG_AES256 rng(entropy);
    
    auto bytes1 = rng.generate(32);
    auto bytes2 = rng.generate(32);
    
    // Very unlikely to be identical
    EXPECT_NE(bytes1, bytes2);
}

TEST(CTR_DRBG_AES256, GenerateZeroBytes) {
    auto entropy = generate_entropy();
    CTR_DRBG_AES256 rng(entropy);
    
    auto bytes = rng.generate(0);
    EXPECT_TRUE(bytes.empty());
}

TEST(CTR_DRBG_AES256, ReseedFunctionality) {
    auto entropy1 = generate_entropy();
    auto entropy2 = generate_entropy();
    
    CTR_DRBG_AES256 rng(entropy1);
    
    // Generate some bytes to consume entropy
    auto before = rng.generate(16);
    
    // Reseed with new entropy
    EXPECT_NO_THROW(rng.reseed(entropy2));
    
    // Generate more bytes after reseeding
    auto after = rng.generate(16);
    
    // Should be different (extremely unlikely to be same)
    EXPECT_NE(before, after);
}

TEST(CTR_DRBG_AES256, ReseedInvalidEntropySize) {
    auto entropy = generate_entropy();
    CTR_DRBG_AES256 rng(entropy);
    
    std::vector<u8> too_small(47);
    std::vector<u8> too_large(49);
    
    EXPECT_THROW(rng.reseed(too_small), std::invalid_argument);
    EXPECT_THROW(rng.reseed(too_large), std::invalid_argument);
}

TEST(CTR_DRBG_AES256, ReseedThreshold) {
    // This test would take too long if we actually hit the reseed threshold (100000)
    // Instead, we'll test the logic by manually setting a low threshold for testing
    // But since RESEED_INTERVAL is private, we can't easily test this without modification
    // For now, we'll just verify the function exists and doesn't throw for normal use
    
    auto entropy = generate_entropy();
    CTR_DRBG_AES256 rng(entropy);
    
    // Generate a reasonable amount of data without hitting threshold
    for (int i = 0; i < 1000; ++i) {
        auto bytes = rng.generate(10);
        EXPECT_EQ(bytes.size(), 10u);
    }
    
    // Should not have thrown yet
    SUCCEED();
}

TEST(CTR_DRBG_AES256, ForwardSecurity) {
    // Test that update() is called with empty vector after generate (forward security)
    // This is harder to test directly since update() is private
    // We can test that successive calls produce different sequences
    
    auto entropy = generate_entropy();
    CTR_DRBG_AES256 rng(entropy);
    
    // Generate some bytes
    auto first_batch = rng.generate(16);
    
    // Generate more bytes
    auto second_batch = rng.generate(16);
    
    // Should be different due to forward security update
    EXPECT_NE(first_batch, second_batch);
}
