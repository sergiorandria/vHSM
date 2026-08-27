#include <gtest/gtest.h>

#include "../../../src/keystore/hsm_object.h"
#include "../../../src/keystore/key_rotation.h"
#include "../../../src/keystore/key_state.h"
#include "../../../src/keystore/key_wrap.h"

#include <vector>

using namespace vhsm::keystore;

namespace {

std::vector<u8> make_kek(u8 seed) {
  std::vector<u8> k(32);
  for (size_t i = 0; i < k.size(); ++i)
    k[i] = static_cast<u8>(seed + i);
  return k;
}

} // namespace

TEST(KeyState, DefaultsToActiveAndRoundTrips) {
  HsmObject obj(ObjectType::PRIVATE_KEY, true, true, false, true);

  // No state attribute set yet -> Active.
  EXPECT_EQ(obj.getKeyState(), KeyState::Active);

  obj.setKeyState(KeyState::Rotating);
  EXPECT_EQ(obj.getKeyState(), KeyState::Rotating);

  obj.setKeyState(KeyState::Revoked);
  EXPECT_EQ(obj.getKeyState(), KeyState::Revoked);

  obj.setKeyState(KeyState::Active);
  EXPECT_EQ(obj.getKeyState(), KeyState::Active);
}

TEST(KeyState, PersistedAsVendorAttribute) {
  HsmObject obj(ObjectType::PRIVATE_KEY);
  obj.setKeyState(KeyState::Rotating);

  const auto *v = obj.findAttribute(CKA_VHSM_KEY_STATE);
  ASSERT_NE(v, nullptr);
  ASSERT_EQ(v->size(), 1u);
  EXPECT_EQ((*v)[0], static_cast<u8>(KeyState::Rotating));

  // Reconstruct from the raw attribute (simulates serialization/restore).
  KeyState restored = static_cast<KeyState>((*v)[0]);
  EXPECT_EQ(restored, KeyState::Rotating);
}

TEST(KeyState, Predicates) {
  EXPECT_TRUE(key_can_sign(KeyState::Active));
  EXPECT_FALSE(key_can_sign(KeyState::Rotating));
  EXPECT_FALSE(key_can_sign(KeyState::Revoked));

  // Rotating keys may still verify/decrypt; revoked may not.
  EXPECT_TRUE(key_can_decrypt(KeyState::Rotating));
  EXPECT_TRUE(key_can_verify(KeyState::Rotating));
  EXPECT_FALSE(key_can_decrypt(KeyState::Revoked));
  EXPECT_FALSE(key_can_verify(KeyState::Revoked));
  EXPECT_FALSE(key_can_wrap(KeyState::Revoked));
}

TEST(KeyRotation, RewrapWrappedReencryptsUnderNewKek) {
  KeyWrap oldKw(make_kek(0x10));
  KeyWrap newKw(make_kek(0x20));

  // A representative wrapped-key blob: 32 bytes of key material.
  std::vector<u8> secret(32);
  for (size_t i = 0; i < secret.size(); ++i)
    secret[i] = static_cast<u8>(i * 7 + 3);

  std::vector<u8> wrapped = oldKw.wrap(secret);

  // Re-encrypt the blob under the new KEK.
  std::vector<u8> rewrapped = key_rewrap_wrapped(oldKw, newKw, wrapped);

  // Unwrapping with the NEW KEK recovers the original secret.
  std::vector<u8> recovered = newKw.unwrap(rewrapped);
  EXPECT_EQ(recovered, secret);

  // Unwrapping the rewrapped blob with the OLD KEK must now fail (fail-closed).
  EXPECT_THROW({ oldKw.unwrap(rewrapped); }, std::runtime_error);
}

TEST(KeyRotation, ConvenienceTransitions) {
  HsmObject obj(ObjectType::PRIVATE_KEY);
  key_mark_rotating(obj);
  EXPECT_EQ(obj.getKeyState(), KeyState::Rotating);
  key_revoke(obj);
  EXPECT_EQ(obj.getKeyState(), KeyState::Revoked);
  key_activate(obj);
  EXPECT_EQ(obj.getKeyState(), KeyState::Active);
}
