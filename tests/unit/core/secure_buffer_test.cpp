#include "gtest/gtest.h"
#include "../../../src/core/secure_buffer.h"

namespace vhsm {
namespace test {

TEST(SecureBufferTest, AllocationAndAccess) {
    // Test allocation
    SecureBuffer buf(10);
    EXPECT_EQ(buf.size(), 10u);
    EXPECT_EQ(buf.byte_size(), 10u);
    EXPECT_NE(buf.data(), nullptr);

    // Test const access
    const SecureBuffer& const_buf = buf;
    EXPECT_EQ(const_buf.size(), 10u);
    EXPECT_EQ(const_buf.byte_size(), 10u);
    EXPECT_NE(const_buf.data(), nullptr);

    // Test default constructor (size 0) - This should fail based on implementation
    // But let's keep the test to see the actual behavior
    EXPECT_THROW(SecureBuffer empty_buf(0);, std::runtime_error);
}

TEST(SecureBufferTest, DataManipulation) {
    SecureBuffer buf(5);

    // Fill with pattern using write method
    uint8_t pattern[5] = {1, 2, 3, 4, 5};
    buf.write(0, pattern, 5);

    // Verify pattern using read method
    uint8_t result[5] = {0};
    buf.read(0, result, 5);
    for (size_t i = 0; i < buf.size(); ++i) {
        EXPECT_EQ(result[i], static_cast<uint8_t>(i + 1));
    }

    // Wipe and verify zeroed
    buf.wipe();
    buf.read(0, result, 5);
    for (size_t i = 0; i < buf.size(); ++i) {
        EXPECT_EQ(result[i], 0u);
    }
}

TEST(SecureBufferTest, MoveSemantics) {
    SecureBuffer buf1(10);
    uint8_t* original_data = buf1.data();

    // Fill with data
    for (size_t i = 0; i < buf1.size(); ++i) {
        buf1.data()[i] = static_cast<uint8_t>(i);
    }

    // Move construct
    SecureBuffer buf2(std::move(buf1));
    EXPECT_EQ(buf2.size(), 10u);
    EXPECT_EQ(buf2.data(), original_data);
    EXPECT_EQ(buf1.size(), 0u);
    EXPECT_EQ(buf1.data(), nullptr);

    // Move assign
    SecureBuffer buf3(5);
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

TEST(SecureBufferTest, WipeFunctionality) {
    SecureBuffer buf(8);

    // Fill with data
    for (size_t i = 0; i < buf.size(); ++i) {
        buf.data()[i] = 0xFF;
    }

    // Wipe should zeroize
    buf.wipe();
    for (size_t i = 0; i < buf.size(); ++i) {
        EXPECT_EQ(buf.data()[i], 0u);
    }

    // Wipe on already wiped buffer should be safe
    buf.wipe();
    for (size_t i = 0; i < buf.size(); ++i) {
        EXPECT_EQ(buf.data()[i], 0u);
    }
}

TEST(SecureBufferTest, EqualityOperators) {
    SecureBuffer buf1(5);
    SecureBuffer buf2(5);
    SecureBuffer buf3(3);

    // Fill buf1 and buf2 with same data
    uint8_t data1[5] = {1, 2, 3, 4, 5};
    uint8_t data2[5] = {1, 2, 3, 4, 5};
    buf1.write(0, data1, 5);
    buf2.write(0, data2, 5);

    // Fill buf3 with different data
    uint8_t data3[3] = {1, 2, 3};
    buf3.write(0, data3, 3);

    // Test equality
    EXPECT_TRUE(buf1 == buf2);
    EXPECT_FALSE(buf1 != buf2);
    EXPECT_FALSE(buf1 == buf3);
    EXPECT_TRUE(buf1 != buf3);

    // Test equals method
    EXPECT_TRUE(buf1.equals(buf2));
    EXPECT_FALSE(buf1.equals(buf3));

    // Test with empty buffers
    SecureBuffer empty1;
    SecureBuffer empty2;
    // Note: Constructor with size 0 throws, so we can't easily test empty buffers
    // This would require changing the constructor to allow size 0
}

TEST(SecureBufferTest, ReadWriteBoundsChecking) {
    SecureBuffer buf(5);

    // Test valid read/write
    uint8_t write_data[3] = {10, 20, 30};
    EXPECT_NO_THROW(buf.write(1, write_data, 3)); // Write 3 bytes at offset 1

    uint8_t read_data[3] = {0};
    EXPECT_NO_THROW(buf.read(1, read_data, 3)); // Read 3 bytes at offset 1
    EXPECT_EQ(read_data[0], 10);
    EXPECT_EQ(read_data[1], 20);
    EXPECT_EQ(read_data[2], 30);

    // Test out of bounds write
    EXPECT_THROW(buf.write(3, write_data, 3), std::out_of_range); // 3+3 > 5
    EXPECT_THROW(buf.write(5, write_data, 1), std::out_of_range); // 5+1 > 5

    // Test out of bounds read
    EXPECT_THROW(buf.read(3, read_data, 3), std::out_of_range); // 3+3 > 5
    EXPECT_THROW(buf.read(5, read_data, 1), std::out_of_range); // 5+1 > 5
}

} // namespace test
} // namespace vhsm