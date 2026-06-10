#include "gtest/gtest.h"
#include "secure_buffer.h"

namespace vhsm {
namespace test {

TEST(SecureBufferTest, AllocationAndAccess) {
    // Test allocation
    SecureBuffer<uint8_t> buf(10);
    EXPECT_EQ(buf.size(), 10u);
    EXPECT_EQ(buf.byte_size(), 10u);
    EXPECT_NE(buf.data(), nullptr);

    // Test const access
    const SecureBuffer<uint8_t>& const_buf = buf;
    EXPECT_EQ(const_buf.size(), 10u);
    EXPECT_EQ(const_buf.byte_size(), 10u);
    EXPECT_NE(const_buf.data(), nullptr);

    // Test default constructor (size 0)
    SecureBuffer<uint8_t> empty_buf;
    EXPECT_EQ(empty_buf.size(), 0u);
    EXPECT_EQ(empty_buf.byte_size(), 0u);
    EXPECT_EQ(empty_buf.data(), nullptr);
}

TEST(SecureBufferTest, DataManipulation) {
    SecureBuffer<uint8_t> buf(5);

    // Fill with pattern
    uint8_t* data = buf.data();
    for (size_t i = 0; i < buf.size(); ++i) {
        data[i] = static_cast<uint8_t>(i + 1);
    }

    // Verify pattern
    for (size_t i = 0; i < buf.size(); ++i) {
        EXPECT_EQ(buf.data()[i], static_cast<uint8_t>(i + 1));
    }

    // Wipe and verify zeroed
    buf.wipe();
    for (size_t i = 0; i < buf.size(); ++i) {
        EXPECT_EQ(buf.data()[i], 0u);
    }
}

TEST(SecureBufferTest, MoveSemantics) {
    SecureBuffer<uint8_t> buf1(10);
    uint8_t* original_data = buf1.data();

    // Fill with data
    for (size_t i = 0; i < buf1.size(); ++i) {
        buf1.data()[i] = static_cast<uint8_t>(i);
    }

    // Move construct
    SecureBuffer<uint8_t> buf2(std::move(buf1));
    EXPECT_EQ(buf2.size(), 10u);
    EXPECT_EQ(buf2.data(), original_data);
    EXPECT_EQ(buf1.size(), 0u);
    EXPECT_EQ(buf1.data(), nullptr);

    // Move assign
    SecureBuffer<uint8_t> buf3(5);
    buf3 = std::move(buf2);
    EXPECT_EQ(buf3.size(), 10u);
    EXPECT_EQ(buf3.data(), original_data);
    EXPECT_EQ(buf2.size(), 0u);
    EXPECT_EQ(buf2.data(), nullptr);

    // Self-move assign should be safe
    buf3 = std::move(buf3);
    EXPECT_EQ(buf3.size(), 10u);
    EXPECT_EQ(buf3.data(), original_data);
}

TEST(SecureBufferTest, ClearFunctionality) {
    SecureBuffer<uint8_t> buf(8);

    // Fill with data
    for (size_t i = 0; i < buf.size(); ++i) {
        buf.data()[i] = 0xFF;
    }

    // Clear should zeroize
    buf.clear();
    for (size_t i = 0; i < buf.size(); ++i) {
        EXPECT_EQ(buf.data()[i], 0u);
    }

    // Clear on already cleared buffer should be safe
    buf.clear();
    for (size_t i = 0; i < buf.size(); ++i) {
        EXPECT_EQ(buf.data()[i], 0u);
    }
}

TEST(SecureBufferTest, DifferentTypes) {
    // Test with different types
    SecureBuffer<int32_t> int_buf(5);
    EXPECT_EQ(int_buf.size(), 5u);
    EXPECT_EQ(int_buf.byte_size(), 5u * sizeof(int32_t));

    SecureBuffer<double> double_buf(3);
    EXPECT_EQ(double_buf.size(), 3u);
    EXPECT_EQ(double_buf.byte_size(), 3u * sizeof(double));

    // Test data manipulation
    int_buf.data()[0] = 42;
    EXPECT_EQ(int_buf.data()[0], 42);

    double_buf.data()[1] = 3.14;
    EXPECT_DOUBLE_EQ(double_buf.data()[1], 3.14);
}

} // namespace test
} // namespace vhsm