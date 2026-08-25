#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>

#include "keystore/token.h"
#include "persistence/token_serializer.h"
#include "persistence/vault.h"

namespace vhsm::persistence {

// End-to-end: a token snapshot is serialized, encrypted in a Vault on disk,
// re-opened with the password, decrypted, and deserialized back into an
// identical snapshot. This exercises the full Phase 7 recovery path.
TEST(VaultSerializerIntegrationTest, TokenStateSurvivesVaultRoundTrip) {
  auto dir = std::filesystem::temp_directory_path() / "vhsm_vault_int_test";
  std::filesystem::create_directories(dir);
  auto path = dir / "token.vault";

  const std::string password = "correct horse battery staple";

  TokenSnapshot before;
  before.label = "integration-token";
  before.id = "tok-0001";
  before.max_session_count = 64;
  before.session_count = 3;
  before.max_rw_session_count = 32;
  before.rw_session_count = 1;
  before.token_initialized = CK_TRUE;
  before.user_pin_set = CK_TRUE;
  before.so_pin_set = CK_FALSE;
  before.user_login_required = CK_TRUE;
  before.so_login_required = CK_FALSE;
  before.max_failed_attempts = 5;
  before.user_failed_attempts = 1;
  before.so_failed_attempts = 0;
  before.user_pin_locked = CK_FALSE;
  before.so_pin_locked = CK_TRUE;
  before.kek = {0xEE, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};

  ASSERT_FALSE(before.kek.empty()) << "snapshot should carry a KEK to persist";
  ASSERT_GT(before.session_count, 0u);

  // Persist through the vault.
  auto vault = Vault::create(path, password, serialize_token_snapshot(before));
  ASSERT_TRUE(vault.is_valid());

  // Reopen (simulating process restart) and recover.
  Vault reopened(path, password);
  ASSERT_TRUE(reopened.is_valid());
  const TokenSnapshot after = deserialize_token_snapshot(reopened.load());

  EXPECT_EQ(after.label, before.label);
  EXPECT_EQ(after.id, before.id);
  EXPECT_EQ(after.session_count, before.session_count);
  EXPECT_EQ(after.rw_session_count, before.rw_session_count);
  EXPECT_EQ(after.user_failed_attempts, before.user_failed_attempts);
  EXPECT_EQ(after.so_failed_attempts, before.so_failed_attempts);
  EXPECT_EQ(after.max_failed_attempts, before.max_failed_attempts);
  EXPECT_EQ(after.kek, before.kek);

  std::filesystem::remove_all(dir);
}

// A vault created by one password must refuse the wrong password even if the
// token snapshot inside is well-formed.
TEST(VaultSerializerIntegrationTest, WrongPasswordRejectsDespiteValidPayload) {
  auto dir = std::filesystem::temp_directory_path() / "vhsm_vault_int_test2";
  std::filesystem::create_directories(dir);
  auto path = dir / "token.vault";

  TokenSnapshot snap;
  snap.label = "label";
  snap.id = "id";
  snap.kek = {1, 2, 3};

  auto vault = Vault::create(path, "secrets", serialize_token_snapshot(snap));
  ASSERT_TRUE(vault.is_valid());

  EXPECT_THROW(Vault(path, "wrong-password"), std::runtime_error);
  std::filesystem::remove_all(dir);
}

// A Token's full durable state survives a vault round-trip via the token-level
// helpers (snapshot_from_token -> Vault::create -> Vault ->
// restore_token_from_vault). This is the exact recovery path the admin
// RestoreToken RPC and C_Finalize autosave follow.
TEST(VaultSerializerIntegrationTest, LiveTokenSurvivesVaultRoundTrip) {
  auto dir = std::filesystem::temp_directory_path() / "vhsm_token_vault_test";
  std::filesystem::remove_all(dir);
  std::filesystem::create_directories(dir);
  auto path = dir / "token.vault";
  const std::string password = "token password";

  // Live token whose durable state we'll persist.
  keystore::Token source("bk-label", "bk-id");
  ASSERT_EQ(
      source.initialize_so_pin(reinterpret_cast<const CK_CHAR *>("9999"), 4),
      CKR_OK);
  ASSERT_EQ(
      source.initialize_user_pin(reinterpret_cast<const CK_CHAR *>("1234"), 4),
      CKR_OK);
  // Pin out 2 failed attempts so the counter has non-default state to carry.
  ASSERT_EQ(
      source.login(CKU_USER, reinterpret_cast<const CK_CHAR *>("0000"), 4),
      CKR_PIN_INCORRECT);
  ASSERT_EQ(
      source.login(CKU_USER, reinterpret_cast<const CK_CHAR *>("0000"), 4),
      CKR_PIN_INCORRECT);

  // Tokens hold no KEK until a wrapping operation generates one; inject a
  // deterministic KEK so the backup/restore has key material to carry.
  const std::vector<u8> kKek = {0xEE, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
  source.restore_state(
      source.is_token_initialized(), source.is_user_pin_set(),
      source.is_so_pin_set(), source.is_user_login_required(),
      source.is_so_login_required(), source.max_pin_attempts(),
      source.user_pin_failed_attempts(), source.so_pin_failed_attempts(),
      source.is_user_pin_locked(), source.is_so_pin_locked(), kKek);
  ASSERT_FALSE(source.get_kek().empty());
  ASSERT_EQ(source.user_pin_failed_attempts(), 2u);

  // Persist: serialize from the live token and encrypt into a fresh vault.
  auto vault = Vault::create(
      path, password, serialize_token_snapshot(snapshot_from_token(source)));
  ASSERT_TRUE(vault.is_valid());

  // Restore: reopen the vault and overwrite a fresh token's durable state.
  // NOTE: Token identity (label/id) is immutable at construction, so the
  // restored token keeps the identity it was created with; everything else
  // (PIN flags, lockout counters, KEK) is carried over.
  keystore::Token restored("restored-label", "restored-id");
  Vault reopened(path, password);
  ASSERT_TRUE(reopened.is_valid());
  restore_token_from_vault(restored, reopened);

  // The restored token must be indistinguishable state-wise from the source.
  EXPECT_EQ(restored.is_user_pin_set(), CK_TRUE);
  EXPECT_EQ(restored.is_so_pin_set(), CK_TRUE);
  EXPECT_EQ(restored.user_pin_failed_attempts(), 2u);
  EXPECT_EQ(restored.so_pin_failed_attempts(), source.so_pin_failed_attempts());
  EXPECT_EQ(restored.max_pin_attempts(), source.max_pin_attempts());
  ASSERT_EQ(restored.get_kek(), kKek);
  ASSERT_FALSE(restored.get_kek().empty()) << "KEK must be carried";

  std::filesystem::remove_all(dir);
}

// Restoring under a wrong password must throw and must NOT partially clobber
// the target token's durable state.
TEST(VaultSerializerIntegrationTest, WrongPasswordDoesNotClobber) {
  auto dir = std::filesystem::temp_directory_path() / "vhsm_token_vault_test2";
  std::filesystem::remove_all(dir);
  std::filesystem::create_directories(dir);
  auto path = dir / "token.vault";

  keystore::Token source("src", "src-id");
  (void)source.initialize_user_pin(reinterpret_cast<const CK_CHAR *>("1234"), 4);
  auto vault =
      Vault::create(path, "right-password",
                    serialize_token_snapshot(snapshot_from_token(source)));
  ASSERT_TRUE(vault.is_valid());

  keystore::Token target("tgt", "tgt-id");
  const auto kek_before = target.get_kek();

  EXPECT_THROW(restore_token_from_vault(target, Vault(path, "wrong-password")),
               std::runtime_error);

  // The failed restore must leave the target untouched.
  EXPECT_EQ(target.get_label(), "tgt");
  EXPECT_EQ(target.get_id(), "tgt-id");
  EXPECT_EQ(target.get_kek(), kek_before);

  std::filesystem::remove_all(dir);
}

} // namespace vhsm::persistence