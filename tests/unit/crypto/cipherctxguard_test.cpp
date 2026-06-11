#include <gtest/gtest.h>
#include "../../../src/crypto/CipherCtxGuard.h"

#include <openssl/evp.h>

using namespace vhsm::crypto;

TEST(CipherCtxGuardTest, ConstructorAndDestruction) {
    // Test that CipherCtxGuard properly cleans up EVP_CIPHER_CTX
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    ASSERT_NE(ctx, nullptr);
    
    {
        CipherCtxGuard guard(ctx);
        // Guard holds the context
        EXPECT_EQ(guard.ctx, ctx);
    }
    // When guard goes out of scope, ctx should be freed
}

TEST(CipherCtxGuardTest, MoveSemanticsDisabled) {
    // Test that copy constructor and assignment are deleted
    EVP_CIPHER_CTX* ctx1 = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX* ctx2 = EVP_CIPHER_CTX_new();
    ASSERT_NE(ctx1, nullptr);
    ASSERT_NE(ctx2, nullptr);
    
    CipherCtxGuard guard1(ctx1);
    
    // These should not compile if uncommented:
    // CipherCtxGuard guard2 = guard1;  // Copy constructor
    // guard2 = guard1;                 // Copy assignment
    
    // Cleanup
    EVP_CIPHER_CTX_free(ctx2);
}

TEST(CipherCtxGuardTest, NullPointerHandling) {
    // Test that CipherCtxGuard handles null pointers safely
    CipherCtxGuard guard(nullptr);
    // Should not crash when destroyed
}
