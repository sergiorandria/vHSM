#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "persistence/kdf.h"

namespace vhsm::persistence {

// Vectors for hkdf_sha256 from RFC 5869 Appendix A.1 (SHA-256, 42-byte output).
TEST(KdfTest, HkdfRfc5869Vector) {
  const std::vector<u8> ikm = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                               0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                               0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
  const std::vector<u8> salt = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
  const std::vector<u8> info = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
                                0xf5, 0xf6, 0xf7, 0xf8, 0xf9};

  const std::vector<u8> okm = {
      0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f,
      0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a,
      0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34,
      0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};

  EXPECT_EQ(hkdf_sha256(ikm, salt, info, 42), okm);
}

TEST(KdfTest, HkdfDeterministicAcrossCalls) {
  const auto out = hkdf_sha256({1, 2, 3}, {}, {'a'}, 32);
  ASSERT_EQ(out.size(), 32u);
  EXPECT_EQ(out, hkdf_sha256({1, 2, 3}, {}, {'a'}, 32));
}

TEST(KdfTest, HkdfEmptySaltAllowedButInputsEnforced) {
  // The DB-HMAC path relies on empty-salt HKDF; ensure it produces a key and
  // that invalid inputs are rejected.
  EXPECT_EQ(hkdf_sha256({9, 9, 9}, {}, {}, 32).size(), 32u);
  EXPECT_THROW(hkdf_sha256({}, {}, {}, 32), std::runtime_error);
  EXPECT_THROW(hkdf_sha256({1}, {}, {}, 0), std::runtime_error);
}

TEST(KdfTest, HkdfChangesWithInputMaterial) {
  EXPECT_NE(hkdf_sha256({1, 2, 3}, {}, {'x'}, 32),
            hkdf_sha256({1, 2, 4}, {}, {'x'}, 32));
}

TEST(KdfTest, DbHmacKeyIsStableAndDependsOnKek) {
  const std::vector<u8> kek = {0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44};
  const auto key = derive_db_hmac_key(kek);
  ASSERT_EQ(key.size(), 32u);

  // Stable across calls (and therefore across process restarts, which is what
  // lets the signature store reopen its DB after a reboot).
  EXPECT_EQ(key, derive_db_hmac_key(kek));

  // Different KEK => different DB HMAC key.
  const std::vector<u8> other = {0xaa, 0xbb, 0xcc, 0xdd,
                                 0x11, 0x22, 0x33, 0x45};
  EXPECT_NE(key, derive_db_hmac_key(other));
}

TEST(KdfTest, VaultKeyChangesWithPasswordIterationsAndSalt) {
  const std::vector<u8> salt = {'s', 'a', 'l', 't'};
  const auto a = derive_vault_key("password", salt, 2, 32);
  ASSERT_EQ(a.size(), 32u);

  // Deterministic for identical inputs.
  EXPECT_EQ(a, derive_vault_key("password", salt, 2, 32));

  // Sensitive to password / salt / iteration count (all wrong guess paths).
  EXPECT_NE(a, derive_vault_key("Password", salt, 2, 32));
  EXPECT_NE(a, derive_vault_key("password", {'s', 'a', 'l', 't', '!'}, 2, 32));
  EXPECT_NE(a, derive_vault_key("password", salt, 3, 32));
}

} // namespace vhsm::persistence