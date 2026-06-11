#include <gtest/gtest.h>
#include "../../../src/crypto/PkeyCtxGuard.h"

#include <openssl/evp.h>

using namespace vhsm::crypto;

TEST(PkeyCtxGuardTest, ConstructorAndDestruction) {
    // Test that PkeyCtxGuard properly cleans up EVP_PKEY_CTX
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(EVP_PKEY_new(), nullptr);
    // Note: In real usage, this would be created with a proper key
    // For testing purposes, we'll test with nullptr which should be handled safely
    
    {
        PkeyCtxGuard guard(ctx);
        // Guard holds the context (even if null)
        EXPECT_EQ(guard.ctx, ctx);
    }
    // When guard goes out of scope, ctx should be freed if not null
}

TEST(PkeyCtxGuardTest, MoveSemanticsDisabled) {
    // Test that copy constructor and assignment are deleted
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx1 = EVP_PKEY_CTX_new(pkey, nullptr);
    EVP_PKEY_CTX* ctx2 = EVP_PKEY_CTX_new(pkey, nullptr);
    
    PkeyCtxGuard guard1(ctx1);
    
    // These should not compile if uncommented:
    // PkeyCtxGuard guard2 = guard1;  // Copy constructor
    // guard2 = guard1;               // Copy assignment
    
    // Cleanup
    EVP_PKEY_CTX_free(ctx2);
    EVP_PKEY_free(pkey);
}

TEST(PkeyCtxGuardTest, NullPointerHandling) {
    // Test that PkeyCtxGuard handles null pointers safely
    PkeyCtxGuard guard(nullptr);
    // Should not crash when destroyed
}

// Test with actual context if we can create one easily
TEST(PkeyCtxGuardTest, ValidContextHandling) {
    // Create a simple PKEY context for testing
    EVP_PKEY* pkey = EVP_PKEY_new();
    ASSERT_NE(pkey, nullptr);
    
    // Create a context for key generation (RSA as example)
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    // Note: This might fail if no engine is available, but we'll test the guard behavior
    
    if (ctx != nullptr) {
        {
            PkeyCtxGuard guard(ctx);
            EXPECT_EQ(guard.ctx, ctx);
        }
        // ctx should be freed by guard
        EVP_PKEY_free(pkey);
    } else {
        // If we couldn't create ctx, just clean up pkey
        EVP_PKEY_free(pkey);
        GTEST_SKIP() << "Could not create EVP_PKEY_CTX for testing";
    }
}
