// admin_service_test.cpp — Unit tests for the gRPC admin auth core.
//
// AdminLoginCore is the transport-agnostic authentication logic behind the
// HsmAdmin gRPC service.  It must:
//   * authenticate an SO/USER PIN against a token (CKR_* semantics),
//   * publish an ADMIN_LOGIN (INFO) event on success,
//   * NOT publish on failed attempts,
//   * respect the token's PIN lockout counter.

#include <gtest/gtest.h>

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "../../../src/admin/admin_service.h"
#include "../../../src/audit/audit_log.h"
#include "../../../src/keystore/token.h"
#include "../../../src/notification/notification_bus.h"
#include "../../../src/notification/notification_event.h"

using vhsm::admin::AdminLoginCore;
using vhsm::audit::AuditLog;
using vhsm::keystore::Token;
using vhsm::notification::NotificationBus;
using vhsm::notification::NotificationEvent;

namespace {

class CapturingNotificationBus final : public NotificationBus {
public:
  void publish(const NotificationEvent &e) override {
    std::lock_guard<std::mutex> lock(m);
    events.push_back(e);
  }
  std::vector<NotificationEvent> events;
  std::mutex m;
};

class CapturingAuditLog final : public AuditLog {
public:
  void append(const std::string &id, const std::string &type) override {
    std::lock_guard<std::mutex> lock(m);
    calls.push_back({id, type});
  }
  struct Call {
    std::string id;
    std::string type;
  };
  std::vector<Call> calls;
  std::mutex m;
};

} // namespace

class AdminLoginCoreTest : public ::testing::Test {
protected:
  void SetUp() override {
    token_ = std::make_unique<Token>("label", "id");
    // Both PINs must exist before login is attempted.
    ASSERT_EQ(token_->initialize_user_pin(
                  reinterpret_cast<const CK_CHAR *>("1234"), 4),
              CKR_OK);
    ASSERT_EQ(
        token_->initialize_so_pin(reinterpret_cast<const CK_CHAR *>("abcd"), 4),
        CKR_OK);
    bus_ = std::make_unique<CapturingNotificationBus>();
    audit_ = std::make_unique<CapturingAuditLog>();
    core_ = std::make_unique<AdminLoginCore>(*token_, bus_.get(), audit_.get());
  }

  std::unique_ptr<Token> token_;
  std::unique_ptr<CapturingNotificationBus> bus_;
  std::unique_ptr<CapturingAuditLog> audit_;
  std::unique_ptr<AdminLoginCore> core_;
};

TEST_F(AdminLoginCoreTest, UserLoginSuccessPublishesAdminLoginEvent) {
  ASSERT_EQ(core_->admin_login(CKU_USER, "1234", "caller-app"), CKR_OK);

  ASSERT_EQ(bus_->events.size(), 1u);
  EXPECT_EQ(bus_->events[0].type, NotificationEvent::EventType::ADMIN_LOGIN);
  EXPECT_EQ(bus_->events[0].severity, NotificationEvent::Severity::INFO);
  EXPECT_EQ(bus_->events[0].source, "admin");
  EXPECT_EQ(bus_->events[0].actor, "caller-app");
  EXPECT_NE(bus_->events[0].summary.find("USER"), std::string::npos);

  ASSERT_EQ(audit_->calls.size(), 1u);
  EXPECT_EQ(audit_->calls[0].type, "ADMIN_LOGIN");
}

TEST_F(AdminLoginCoreTest, SoLoginSuccessPublishesWithSoRole) {
  ASSERT_EQ(core_->admin_login(CKU_SO, "abcd", ""), CKR_OK);

  ASSERT_EQ(bus_->events.size(), 1u);
  EXPECT_EQ(bus_->events[0].type, NotificationEvent::EventType::ADMIN_LOGIN);
  EXPECT_EQ(bus_->events[0].actor, "SO"); // callers may be anonymous
  EXPECT_NE(bus_->events[0].summary.find("SO"), std::string::npos);
  EXPECT_NE(bus_->events[0].detail_json.find("\"SO\""), std::string::npos);
}

TEST_F(AdminLoginCoreTest, WrongPinDoesNotPublishEvent) {
  EXPECT_EQ(core_->admin_login(CKU_USER, "0000", "attacker"),
            CKR_PIN_INCORRECT);
  EXPECT_TRUE(bus_->events.empty());
  EXPECT_TRUE(audit_->calls.empty());
}

TEST_F(AdminLoginCoreTest, InvalidUserTypeRejected) {
  EXPECT_EQ(core_->admin_login(static_cast<CK_USER_TYPE>(77), "1234", ""),
            CKR_USER_TYPE_INVALID);
  EXPECT_TRUE(bus_->events.empty());
}

TEST_F(AdminLoginCoreTest, RepeatedFailuresLockPinAndPublishNothing) {
  // Trip the lockout (default threshold is 5).
  for (int i = 0; i < 5; ++i) {
    core_->admin_login(CKU_USER, "wrong", "bruteforcer");
  }
  // Correct PIN is now rejected; still nothing was published.
  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(core_->admin_login(CKU_USER, "1234", "late-caller"),
              CKR_PIN_LOCKED);
  }
  EXPECT_TRUE(bus_->events.empty());
  EXPECT_TRUE(audit_->calls.empty());
}

TEST_F(AdminLoginCoreTest, DoesNotPublishWhenBusOrAuditMissing) {
  AdminLoginCore core_without_bus(*token_, nullptr, nullptr);
  // Bus null but session(audit) only checked under a shared success path:
  // with both null, no throw, just no event.
  EXPECT_EQ(core_without_bus.admin_login(CKU_USER, "1234", "x"), CKR_OK);
}

TEST_F(AdminLoginCoreTest, BusNullAuditPresentStillSucceeds) {
  AdminLoginCore core_without_bus(*token_, nullptr, audit_.get());
  EXPECT_EQ(core_without_bus.admin_login(CKU_USER, "1234", "x"), CKR_OK);
  EXPECT_TRUE(audit_->calls.empty()); // no audit write because bus missing
}

// ---------------------------------------------------------------------------
// TokenBackupCore — Backup/Restore of the token's durable state through a vault
// file (PLAN.md §8). Round-trips KEK + PIN flags + lockout state.
// ---------------------------------------------------------------------------

#include <filesystem>

#include "../../../src/persistence/token_serializer.h"

using vhsm::admin::TokenBackupCore;

namespace {
const std::vector<uint8_t> kKek = {0xEE, 0x11, 0x22, 0x33,
                                   0x44, 0x55, 0x66, 0x77};
}

class TokenBackupCoreTest : public ::testing::Test {
protected:
  void SetUp() override {
    dir_ = std::filesystem::temp_directory_path() / "vhsm_admin_bkp_test";
    std::filesystem::create_directories(dir_);
    path_ = dir_ / "token.vault";
    token_ = std::make_unique<Token>("backup-label", "backup-id");
    ASSERT_EQ(token_->initialize_user_pin(
                  reinterpret_cast<const CK_CHAR *>("1234"), 4),
              CKR_OK);
    // Inject a KEK (a fresh token has none until a wrap operation runs) so
    // the backup has key material to carry through the vault.
    token_->restore_state(
        token_->is_token_initialized(), token_->is_user_pin_set(),
        token_->is_so_pin_set(), token_->is_user_login_required(),
        token_->is_so_login_required(), token_->max_pin_attempts(),
        token_->user_pin_failed_attempts(), token_->so_pin_failed_attempts(),
        token_->is_user_pin_locked(), token_->is_so_pin_locked(), kKek);
    ASSERT_FALSE(token_->get_kek().empty());
    core_ = std::make_unique<TokenBackupCore>(*token_);
  }

  void TearDown() override { std::filesystem::remove_all(dir_); }

  std::filesystem::path dir_;
  std::filesystem::path path_;
  std::unique_ptr<Token> token_;
  std::unique_ptr<TokenBackupCore> core_;
};

TEST_F(TokenBackupCoreTest, BackupRestoreRoundTrip) {
  // Mutate state so the backup carries non-trivial durable state.
  ASSERT_EQ(
      token_->login(CKU_USER, reinterpret_cast<const CK_CHAR *>("0000"), 4),
      CKR_PIN_INCORRECT);
  ASSERT_EQ(
      token_->login(CKU_USER, reinterpret_cast<const CK_CHAR *>("0000"), 4),
      CKR_PIN_INCORRECT);
  const auto kek_before = token_->get_kek();
  ASSERT_FALSE(kek_before.empty());

  core_->backup(path_.string(), "vault-password");

  // Restore into a distinct token.  Token identity is immutable at
  // construction, so the restored token keeps its own label/id; the durable
  // state (PIN flags, lockout counters, KEK) must be carried over.
  Token fresh("fresh-label", "fresh-id");
  TokenBackupCore restore_core(fresh);
  restore_core.restore(path_.string(), "vault-password");

  EXPECT_EQ(fresh.get_label(), "fresh-label");
  EXPECT_EQ(fresh.get_id(), "fresh-id");
  EXPECT_EQ(fresh.is_user_pin_set(), CK_TRUE);
  EXPECT_EQ(fresh.user_pin_failed_attempts(), 2u);
  EXPECT_EQ(fresh.get_kek(), kek_before);
}

TEST_F(TokenBackupCoreTest, BackupRefusesExistingFile) {
  core_->backup(path_.string(), "pw");
  // A second backup at the same path must fail (vault must not be clobbered).
  EXPECT_THROW(core_->backup(path_.string(), "pw"), std::runtime_error);
}

TEST_F(TokenBackupCoreTest, RestoreWrongPasswordThrows) {
  core_->backup(path_.string(), "right-password");
  Token fresh("f", "f-id");
  TokenBackupCore restore_core(fresh);
  EXPECT_THROW(restore_core.restore(path_.string(), "wrong-password"),
               std::runtime_error);
  // Failed restore must not clobber the target token.
  EXPECT_EQ(fresh.get_label(), "f");
  EXPECT_EQ(fresh.get_id(), "f-id");
  EXPECT_TRUE(fresh.get_kek().empty());
}

TEST_F(TokenBackupCoreTest, BackupMissingFileRestoreThrows) {
  Token fresh("f", "f-id");
  TokenBackupCore restore_core(fresh);
  const auto kek_before = fresh.get_kek();
  EXPECT_THROW(
      restore_core.restore((dir_ / "does-not-exist.vault").string(), "pw"),
      std::runtime_error);
  EXPECT_EQ(fresh.get_kek(), kek_before);
}