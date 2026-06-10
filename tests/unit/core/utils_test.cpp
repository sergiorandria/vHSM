// ---------------------------------------------------------------------------
// tests/unit/utils/utils_test.cpp
// ---------------------------------------------------------------------------
#include "../../../src/core/utils.h"
#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <regex>
#include <set>
#include <string>

using namespace vhsm::utils;

// Convenience: build a span<const byte> from a string literal
static std::span<const std::byte> as_bytes(std::string_view s) {
    return { reinterpret_cast<const std::byte*>(s.data()), s.size() };
}

// Convenience: bytes → string (for readable assertions)
static std::string to_str(const std::vector<std::byte>& v) {
    return { reinterpret_cast<const char*>(v.data()), v.size() };
}

// ===========================================================================
// UUID v4
// ===========================================================================

TEST(UuidV4, CorrectLength) {
    EXPECT_EQ(uuid_v4().size(), 36u);
}

TEST(UuidV4, CorrectFormat) {
    // "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
    const std::regex re(
        "^[0-9a-f]{8}-"
        "[0-9a-f]{4}-"
        "4[0-9a-f]{3}-"
        "[89ab][0-9a-f]{3}-"
        "[0-9a-f]{12}$");
    for (int i = 0; i < 50; ++i)
        EXPECT_TRUE(std::regex_match(uuid_v4(), re)) << "bad UUID: " << uuid_v4();
}

TEST(UuidV4, Version4BitSet) {
    // Character at index 14 must always be '4'
    for (int i = 0; i < 20; ++i)
        EXPECT_EQ(uuid_v4()[14], '4');
}

TEST(UuidV4, VariantBitSet) {
    // Character at index 19 must be one of '8','9','a','b'
    const std::string valid = "89ab";
    for (int i = 0; i < 20; ++i)
        EXPECT_NE(valid.find(uuid_v4()[19]), std::string::npos)
            << "bad variant nibble at [19]: " << uuid_v4()[19];
}

TEST(UuidV4, Uniqueness) {
    std::set<std::string> seen;
    for (int i = 0; i < 1000; ++i)
        seen.insert(uuid_v4());
    // Probability of a collision in 1000 UUIDs is astronomically small
    EXPECT_EQ(seen.size(), 1000u);
}

TEST(UuidV4, DashesInCorrectPositions) {
    const auto u = uuid_v4();
    EXPECT_EQ(u[8],  '-');
    EXPECT_EQ(u[13], '-');
    EXPECT_EQ(u[18], '-');
    EXPECT_EQ(u[23], '-');
}

// ===========================================================================
// Base64 — encoding
// ===========================================================================

TEST(Base64Encode, EmptyInput) {
    EXPECT_EQ(base64_encode({}), "");
}

TEST(Base64Encode, OneByte) {
    // 0x4d ('M') → "TQ=="
    EXPECT_EQ(base64_encode(as_bytes("M")), "TQ==");
}

TEST(Base64Encode, TwoBytes) {
    // "Ma" → "TWE="
    EXPECT_EQ(base64_encode(as_bytes("Ma")), "TWE=");
}

TEST(Base64Encode, ThreeBytes_NoPadding) {
    // "Man" → "TWFu"
    EXPECT_EQ(base64_encode(as_bytes("Man")), "TWFu");
}

TEST(Base64Encode, RFC4648TestVectors) {
    // Vectors from RFC 4648 §10
    EXPECT_EQ(base64_encode(as_bytes("")),       "");
    EXPECT_EQ(base64_encode(as_bytes("f")),      "Zg==");
    EXPECT_EQ(base64_encode(as_bytes("fo")),     "Zm8=");
    EXPECT_EQ(base64_encode(as_bytes("foo")),    "Zm9v");
    EXPECT_EQ(base64_encode(as_bytes("foob")),   "Zm9vYg==");
    EXPECT_EQ(base64_encode(as_bytes("fooba")),  "Zm9vYmE=");
    EXPECT_EQ(base64_encode(as_bytes("foobar")), "Zm9vYmFy");
}

TEST(Base64Encode, AllByteValues) {
    // Encode all 256 byte values — should not crash or produce garbage.
    std::vector<std::byte> all(256);
    for (int i = 0; i < 256; ++i)
        all[i] = static_cast<std::byte>(i);
    const auto enc = base64_encode(all);
    EXPECT_EQ(enc.size(), ((256 + 2) / 3) * 4);
    // Every character must be a valid base64 character or '='
    for (char c : enc)
        EXPECT_NE(std::string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=").find(c),
                  std::string::npos) << "unexpected char: " << c;
}

// ===========================================================================
// Base64 — decoding
// ===========================================================================

TEST(Base64Decode, EmptyInput) {
    const auto r = base64_decode("");
    ASSERT_TRUE(r.has_value());
    EXPECT_TRUE(r->empty());
}

TEST(Base64Decode, RFC4648TestVectors) {
    EXPECT_EQ(to_str(*base64_decode("Zg==")),     "f");
    EXPECT_EQ(to_str(*base64_decode("Zm8=")),     "fo");
    EXPECT_EQ(to_str(*base64_decode("Zm9v")),     "foo");
    EXPECT_EQ(to_str(*base64_decode("Zm9vYg==")), "foob");
    EXPECT_EQ(to_str(*base64_decode("Zm9vYmE=")), "fooba");
    EXPECT_EQ(to_str(*base64_decode("Zm9vYmFy")), "foobar");
}

TEST(Base64Decode, RejectsLengthNotMultipleOf4) {
    EXPECT_FALSE(base64_decode("Zg=").has_value());
    EXPECT_FALSE(base64_decode("Zg").has_value());
    EXPECT_FALSE(base64_decode("Z").has_value());
}

TEST(Base64Decode, RejectsInvalidCharacters) {
    EXPECT_FALSE(base64_decode("Zm9!").has_value());
    EXPECT_FALSE(base64_decode("Zm 9").has_value());
    EXPECT_FALSE(base64_decode("Zm\x009v").has_value());
}

TEST(Base64Decode, RejectsMidStringPadding) {
    // "TQ==" is valid on its own, but "TQ==Zg==" has padding mid-string
    EXPECT_FALSE(base64_decode("TQ==Zg==").has_value());
}

TEST(Base64Decode, RejectsInvalidPaddingPattern) {
    // "xx=x" — pad at position 2 but not 3
    EXPECT_FALSE(base64_decode("Zm=v").has_value());
}

// ===========================================================================
// Base64 — round-trip
// ===========================================================================

TEST(Base64RoundTrip, ArbitraryBytes) {
    const std::vector<std::byte> original = {
        std::byte{0x00}, std::byte{0xff}, std::byte{0x80},
        std::byte{0x01}, std::byte{0xfe}, std::byte{0x7f}
    };
    const auto encoded = base64_encode(original);
    const auto decoded = base64_decode(encoded);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, original);
}

TEST(Base64RoundTrip, AllByteValues) {
    std::vector<std::byte> all(256);
    for (int i = 0; i < 256; ++i)
        all[i] = static_cast<std::byte>(i);
    const auto back = base64_decode(base64_encode(all));
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(*back, all);
}

TEST(Base64RoundTrip, LengthModulo3Cases) {
    // len % 3 == 0
    EXPECT_EQ(to_str(*base64_decode(base64_encode(as_bytes("abc")))), "abc");
    // len % 3 == 1
    EXPECT_EQ(to_str(*base64_decode(base64_encode(as_bytes("a")))),   "a");
    // len % 3 == 2
    EXPECT_EQ(to_str(*base64_decode(base64_encode(as_bytes("ab")))),  "ab");
}

// ===========================================================================
// Hex — encoding
// ===========================================================================

TEST(HexEncode, EmptyInput) {
    EXPECT_EQ(hex_encode({}), "");
}

TEST(HexEncode, SingleZeroByte) {
    const std::byte b{0x00};
    EXPECT_EQ(hex_encode({&b, 1}), "00");
}

TEST(HexEncode, SingleMaxByte) {
    const std::byte b{0xff};
    EXPECT_EQ(hex_encode({&b, 1}), "ff");
}

TEST(HexEncode, KnownSequence) {
    const std::vector<std::byte> data = {
        std::byte{0xde}, std::byte{0xad}, std::byte{0xbe}, std::byte{0xef}
    };
    EXPECT_EQ(hex_encode(data), "deadbeef");
}

TEST(HexEncode, OutputIsLowercase) {
    const std::vector<std::byte> data = {
        std::byte{0xab}, std::byte{0xcd}, std::byte{0xef}
    };
    const auto enc = hex_encode(data);
    EXPECT_EQ(enc, std::string("abcdef"));
    for (char c : enc)
        EXPECT_EQ(c, std::tolower(c));
}

TEST(HexEncode, OutputLengthIsDoubleInput) {
    for (std::size_t n : {0u, 1u, 2u, 7u, 16u, 33u}) {
        std::vector<std::byte> v(n, std::byte{0xaa});
        EXPECT_EQ(hex_encode(v).size(), n * 2);
    }
}

// ===========================================================================
// Hex — decoding
// ===========================================================================

TEST(HexDecode, EmptyInput) {
    const auto r = hex_decode("");
    ASSERT_TRUE(r.has_value());
    EXPECT_TRUE(r->empty());
}

TEST(HexDecode, KnownSequence) {
    const auto r = hex_decode("deadbeef");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ((*r)[0], std::byte{0xde});
    EXPECT_EQ((*r)[1], std::byte{0xad});
    EXPECT_EQ((*r)[2], std::byte{0xbe});
    EXPECT_EQ((*r)[3], std::byte{0xef});
}

TEST(HexDecode, AcceptsUppercase) {
    const auto lo = hex_decode("deadbeef");
    const auto hi = hex_decode("DEADBEEF");
    ASSERT_TRUE(lo.has_value());
    ASSERT_TRUE(hi.has_value());
    EXPECT_EQ(*lo, *hi);
}

TEST(HexDecode, AcceptsMixedCase) {
    const auto r = hex_decode("DeAdBeEf");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ((*r)[0], std::byte{0xde});
}

TEST(HexDecode, RejectsOddLength) {
    EXPECT_FALSE(hex_decode("a").has_value());
    EXPECT_FALSE(hex_decode("abc").has_value());
    EXPECT_FALSE(hex_decode("deadbee").has_value());
}

TEST(HexDecode, RejectsInvalidCharacters) {
    EXPECT_FALSE(hex_decode("zz").has_value());
    EXPECT_FALSE(hex_decode("0g").has_value());
    EXPECT_FALSE(hex_decode("de ad").has_value()); // space
    EXPECT_FALSE(hex_decode("de:ad").has_value()); // colon
}

// ===========================================================================
// Hex — round-trip
// ===========================================================================

TEST(HexRoundTrip, AllByteValues) {
    std::vector<std::byte> all(256);
    for (int i = 0; i < 256; ++i)
        all[i] = static_cast<std::byte>(i);
    const auto back = hex_decode(hex_encode(all));
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(*back, all);
}

TEST(HexRoundTrip, ArbitraryString) {
    const std::string original = "Hello, vHSM!";
    const auto enc  = hex_encode(as_bytes(original));
    const auto back = hex_decode(enc);
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(to_str(*back), original);
}