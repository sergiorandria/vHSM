// Unit tests for SignContext
// Verifies construction, property accessors, data accumulation, clearing and
// error handling for invalid inputs.

#include <gtest/gtest.h>
#include <string>

#include "../../../src/session/SignContext.h"
#include "../../../src/core/error.h"
#include "../../../src/core/types.h"

using namespace vhsm::session;

// Test correct initialization and initial state
TEST(SignContextTest, InitializationAndProperties) {
    CK_MECHANISM_TYPE mech = CKM_SHA256_RSA_PKCS;
    CK_OBJECT_HANDLE key = 77;

    SignContext ctx(mech, key);

    EXPECT_EQ(ctx.mechanism(), mech);
    EXPECT_EQ(ctx.key_handle(), key);
    EXPECT_TRUE(ctx.data().empty()); // buffer should be empty
}

// Passing an invalid key handle must throw
TEST(SignContextTest, ThrowsOnInvalidKeyHandle) {
    EXPECT_THROW(SignContext(CKM_SHA256_RSA_PKCS, CKR_OBJECT_HANDLE_INVALID), CryptoException);
}

// Accumulate multiple chunks of data and verify concatenation
TEST(SignContextTest, AccumulateDataSuccessively) {
    SignContext ctx(CKM_SHA256_RSA_PKCS, 1);

    std::string part1 = "Segment_1 ";
    std::string part2 = "Segment_2";

    // First chunk
    ctx.update(reinterpret_cast<const uint8_t*>(part1.data()), part1.size());
    // Second chunk (appended)
    ctx.update(reinterpret_cast<const uint8_t*>(part2.data()), part2.size());

    // Convert internal buffer for verification
    const auto& buffer = ctx.data();
    std::string final_result(buffer.begin(), buffer.end());

    EXPECT_EQ(final_result, "Segment_1 Segment_2");
    EXPECT_EQ(buffer.size(), part1.size() + part2.size());
}

// Clear should reset the accumulator
TEST(SignContextTest, ClearResetsAccumulator) {
    SignContext ctx(CKM_SHA256_RSA_PKCS, 1);
    std::string data = "Confidential cryptographic data";

    ctx.update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    ASSERT_FALSE(ctx.data().empty());

    ctx.clear();
    EXPECT_TRUE(ctx.data().empty());
}

// Robustness: null pointer with positive length must throw; null with zero len is allowed
TEST(SignContextTest, RejectsNullPointerWithPositiveLength) {
    SignContext ctx(CKM_SHA256_RSA_PKCS, 1);

    EXPECT_THROW(ctx.update(nullptr, 32), CryptoException);
    EXPECT_NO_THROW(ctx.update(nullptr, 0));
}