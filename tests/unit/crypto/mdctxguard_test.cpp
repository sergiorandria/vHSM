#include <gtest/gtest.h>
#include "../../../src/crypto/MdCtxGuard.h"

#include <openssl/evp.h>

using namespace vhsm::crypto;

TEST(MdCtxGuardTest, ConstructorAndDestruction) {
    // Test that MdCtxGuard properly cleans up EVP_MD_CTX
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    ASSERT_NE(ctx, nullptr);
    
    {
        MdCtxGuard guard(ctx);
        // Guard holds the context, but we can still use it
        EXPECT_EQ(guard.ctx, ctx);
    }
    // When guard goes out of scope, ctx should be freed
    // We can't easily test that it's freed without causing UB by using freed memory
    // But we can verify the guard doesn't leak by construction/destruction
}

TEST(MdCtxGuardTest, MoveSemanticsDisabled) {
    // Test that copy constructor and assignment are deleted
    EVP_MD_CTX* ctx1 = EVP_MD_CTX_new();
    EVP_MD_CTX* ctx2 = EVP_MD_CTX_new();
    ASSERT_NE(ctx1, nullptr);
    ASSERT_NE(ctx2, nullptr);
    
    MdCtxGuard guard1(ctx1);
    
    // These should not compile if uncommented:
    // MdCtxGuard guard2 = guard1;  // Copy constructor
    // guard2 = guard1;             // Copy assignment
    
    // Cleanup
    EVP_MD_CTX_free(ctx2);
}

TEST(MdCtxGuardTest, NullPointerHandling) {
    // Test that MdCtxGuard handles null pointers safely
    MdCtxGuard guard(nullptr);
    // Should not crash when destroyed
}
