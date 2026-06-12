// Unit tests for FindContext
// Verifies iteration, reset, overflow handling and empty-list behavior.

#include <gtest/gtest.h>
#include "../../../src/session/FindContext.h"

// Test the nominal iteration over a list of object handles
TEST(FindContextTest, NominalIteration) {
    std::vector<ObjectHandle> handles = {101, 102, 103};
    FindContext ctx(handles);

    // Check presence and value of each element
    ASSERT_TRUE(ctx.has_next());
    EXPECT_EQ(ctx.next(), 101);

    ASSERT_TRUE(ctx.has_next());
    EXPECT_EQ(ctx.next(), 102);

    ASSERT_TRUE(ctx.has_next());
    EXPECT_EQ(ctx.next(), 103);

    // End of list reached
    EXPECT_FALSE(ctx.has_next());
}

// Test that reset brings the cursor back to the start
TEST(FindContextTest, ResetBringsCursorBackToStart) {
    FindContext ctx(std::vector<ObjectHandle>{42, 99});

    EXPECT_EQ(ctx.next(), 42);
    
    // Reset the internal index cursor
    ctx.reset();
    
    // We should be able to iterate from the beginning again
    EXPECT_TRUE(ctx.has_next());
    EXPECT_EQ(ctx.next(), 42);
}

// Safety test: out-of-bounds next() must throw
TEST(FindContextTest, ThrowsExceptionOnOverflow) {
    FindContext ctx(std::vector<ObjectHandle>{500});

    EXPECT_EQ(ctx.next(), 500);
    EXPECT_FALSE(ctx.has_next());

    // Calling next() when has_next() is false must throw HsmException
    EXPECT_THROW(ctx.next(), HsmException);
}

// Behavior when the initial list is empty
TEST(FindContextTest, EmptyListBehavior) {
    FindContext ctx(std::vector<ObjectHandle>{});

    EXPECT_FALSE(ctx.has_next());
    EXPECT_THROW(ctx.next(), HsmException);
}