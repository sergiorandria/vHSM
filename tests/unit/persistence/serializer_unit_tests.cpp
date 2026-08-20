#include <gtest/gtest.h>

#include <cstring>

#include "persistence/token_serializer.h"

namespace vhsm::persistence {

namespace {

// A snapshot with every interesting field set to a non-default value.
TokenSnapshot make_snapshot() {
  TokenSnapshot s;
  s.label = "Test Token";
  s.id = "tok-42";
  s.max_session_count = 64;
  s.session_count = 3;
  s.max_rw_session_count = 32;
  s.rw_session_count = 1;
  s.token_initialized = CK_TRUE;
  s.user_pin_set = CK_TRUE;
  s.so_pin_set = CK_FALSE;
  s.user_login_required = CK_TRUE;
  s.so_login_required = CK_FALSE;
  s.max_failed_attempts = 10;
  s.user_failed_attempts = 2;
  s.so_failed_attempts = 0;
  s.user_pin_locked = CK_FALSE;
  s.so_pin_locked = CK_TRUE;
  s.kek = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
  return s;
}

} // namespace

TEST(TokenSerializerTest, RoundTripFullSnapshot) {
  TokenSnapshot s = make_snapshot();
  auto bytes = serialize_token_snapshot(s);
  TokenSnapshot out = deserialize_token_snapshot(bytes);

  EXPECT_EQ(out.label, s.label);
  EXPECT_EQ(out.id, s.id);
  EXPECT_EQ(out.max_session_count, s.max_session_count);
  EXPECT_EQ(out.session_count, s.session_count);
  EXPECT_EQ(out.max_rw_session_count, s.max_rw_session_count);
  EXPECT_EQ(out.rw_session_count, s.rw_session_count);
  EXPECT_EQ(out.token_initialized, s.token_initialized);
  EXPECT_EQ(out.user_pin_set, s.user_pin_set);
  EXPECT_EQ(out.so_pin_set, s.so_pin_set);
  EXPECT_EQ(out.user_login_required, s.user_login_required);
  EXPECT_EQ(out.so_login_required, s.so_login_required);
  EXPECT_EQ(out.max_failed_attempts, s.max_failed_attempts);
  EXPECT_EQ(out.user_failed_attempts, s.user_failed_attempts);
  EXPECT_EQ(out.so_failed_attempts, s.so_failed_attempts);
  EXPECT_EQ(out.user_pin_locked, s.user_pin_locked);
  EXPECT_EQ(out.so_pin_locked, s.so_pin_locked);
  EXPECT_EQ(out.kek, s.kek);
}

TEST(TokenSerializerTest, EmptySnapshotRoundTrip) {
  TokenSnapshot s;
  auto out = deserialize_token_snapshot(serialize_token_snapshot(s));
  EXPECT_EQ(out.label, "");
  EXPECT_EQ(out.id, "");
  EXPECT_TRUE(out.kek.empty());
}

TEST(TokenSerializerTest, RejectsGarbage) {
  EXPECT_THROW(deserialize_token_snapshot({}), std::runtime_error);
  EXPECT_THROW(deserialize_token_snapshot({0x00}), std::runtime_error);
  EXPECT_THROW(deserialize_token_snapshot({0xFF, 0xFF, 0xFF, 0xFF, 0xFF}),
               std::runtime_error);
}

TEST(TokenSerializerTest, RejectsUnknownVersion) {
  std::vector<u8> bytes = serialize_token_snapshot(make_snapshot());
  // Version is the second u32 (bytes 4..7, little-endian). Set it to zero.
  bytes[4] = 0;
  bytes[5] = 0;
  bytes[6] = 0;
  bytes[7] = 0;
  EXPECT_THROW(deserialize_token_snapshot(bytes), std::runtime_error);
}

TEST(TokenSerializerTest, DeterministicNoSalt) {
  // Serialization must be non-random (no salt/nonce) so identical snapshots
  // produce identical bytes — required for vault corruption detection.
  TokenSnapshot s = make_snapshot();
  EXPECT_EQ(serialize_token_snapshot(s), serialize_token_snapshot(s));
}

} // namespace vhsm::persistence