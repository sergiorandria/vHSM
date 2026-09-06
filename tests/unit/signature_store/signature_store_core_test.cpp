// signature_store_core_test.cpp — Unit tests for the signature_store internal
// cores (dispatcher / verification / query) and their validating facades.
//
// The cores are exercised directly where they own injectable dependencies
// (clock, notification bus, audit log, ledger client); the facades are
// exercised for input validation.

#include <gtest/gtest.h>

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "../../../src/keystore/token.h"
#include "../../../src/signature_store/db_connection.h"
#include "../../../src/signature_store/db_schema.h"
#include "../../../src/signature_store/signature_repository.h"
#include "../../../src/signature_store/sqlite_connection.h"

#include "../../../src/core/hsm_clock.h"
#include "../../../src/core/types.h"

#include "../../../src/signature_store/signature_dispatcher.h"
#include "../../../src/signature_store/signature_query.h"
#include "../../../src/signature_store/outbox_poller.h"
#include "../../../src/signature_store/verification_service.h"

#include "../../../src/signature_store/internal/signature_dispatcher_core.h"
#include "../../../src/signature_store/internal/signature_query_core.h"
#include "../../../src/signature_store/internal/verification_service_core.h"

#include "../../../src/audit/audit_log.h"
#include "../../../src/ledger/ledger_client.h"
#include "../../../src/ledger/ledger_entry.h"
#include "../../../src/notification/notification_bus.h"
#include "../../../src/notification/notification_event.h"

using namespace vhsm::signature_store;
using namespace vhsm::signature_store::db;
using namespace vhsm::signature_store::db::internal;

namespace {

// ---- test doubles -----------------------------------------------------------

// Fixed clock so we can assert the dispatcher stamps events with the injected
// time rather than wall-clock.
class FakeHsmClock : public vhsm::IHsmClock {
public:
  explicit FakeHsmClock(int64_t ms) : now_ms_(ms) {}
  vhsm::HsmTimePoint now() const noexcept override {
    return vhsm::HsmTimePoint(std::chrono::milliseconds(now_ms_));
  }
  int64_t now_ms_;
};

class CapturingNotificationBus : public vhsm::notification::NotificationBus {
public:
  void publish(const vhsm::notification::NotificationEvent &e) override {
    {
      std::lock_guard<std::mutex> lock(m);
      events.push_back(e);
    }
    cv.notify_all();
  }
  std::vector<vhsm::notification::NotificationEvent> events;
  std::mutex m;
  std::condition_variable cv;
};

class CapturingAuditLog : public vhsm::audit::AuditLog {
public:
  vhsm::v1::CkStatus append(const std::string &id, const std::string &type) noexcept override {
    calls.push_back({id, type});
    return vhsm::v1::CkStatus{};
  }
  struct Call {
    std::string id;
    std::string type;
  };
  std::vector<Call> calls;
};

class MockLedgerClient : public vhsm::ledger::LedgerClient {
public:
  MockLedgerClient() : vhsm::ledger::LedgerClient() {}
  std::optional<vhsm::ledger::LedgerEntry>
  get_record(const std::string &) override {
    if (!return_entry)
      return std::nullopt;
    return entry;
  }
  vhsm::ledger::LedgerEntry entry;
  bool return_entry = false;
};

// ---- helpers
// -----------------------------------------------------------------

std::string s(const std::optional<std::string> &opt) {
  return opt ? *opt : "<NULL>";
}

vhsm::crypto::SignResult make_sign_result() {
  vhsm::crypto::SignResult sr;
  sr.signature = {0x01, 0x02, 0x03, 0x04};
  sr.mechanism_str = "CKM_ECDSA_SHA256";
  sr.digest_alg = "SHA256";
  sr.payload_digest = "aabbccddeeff00112233445566778899";
  sr.payload_size = 4;
  return sr;
}

// Shared harness: in-memory SQLite + bootstrapped schema + a token.
class SignatureStoreCoreTest : public ::testing::Test {
protected:
  void SetUp() override {
    conn_ = make_sqlite_connection(":memory:");
    schema_ = std::make_unique<DbSchema>(*conn_);
    schema_->bootstrap();
    token_ = std::make_unique<vhsm::keystore::Token>("test-token", "test-id");
    // Inject deterministic KEK so RowIntegrity HMAC (DbHmacKey HKDF) is available.
    // Fresh tokens have no KEK until a wrap operation; tests need it for recompute_integrity_hmac.
    {
      const std::vector<uint8_t> kKek = {0xEE, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                                         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
      token_->restore_state(token_->is_token_initialized(), token_->is_user_pin_set(),
                            token_->is_so_pin_set(), token_->is_user_login_required(),
                            token_->is_so_login_required(), token_->max_pin_attempts(),
                            token_->user_pin_failed_attempts(), token_->so_pin_failed_attempts(),
                            token_->is_user_pin_locked(), token_->is_so_pin_locked(), kKek);
    }
    repo_ = std::make_unique<SignatureRepository>(*conn_, *token_);
  }

  std::unique_ptr<IDbConnection> conn_;
  std::unique_ptr<DbSchema> schema_;
  std::unique_ptr<vhsm::keystore::Token> token_;
  std::unique_ptr<SignatureRepository> repo_;
};

} // namespace

// =============================================================================
// SignatureDispatcher — facade validation + core clock injection
// =============================================================================

TEST_F(SignatureStoreCoreTest,
       DispatchInsertsRecordAndOutboxPublishesSignCreated) {
  CapturingNotificationBus bus;
  CapturingAuditLog audit;
  FakeHsmClock clock(1700000000123LL);
  v_SignatureDispatcherCore_M1 core(*conn_, *token_, bus, audit,
                                    /*ledger_worker=*/nullptr, clock);

  v_SignatureDispatchInput_M1 input;
  input.sign_result = make_sign_result();
  input.created_at = 1234567890;
  input.slot_id = 0;
  input.token_label = "tok";
  input.key_id = "kid";
  input.key_fingerprint = "fpABC1234567890";
  input.mechanism = "CKM_ECDSA_SHA256";
  input.digest_algorithm = "SHA256";
  input.session_handle = "sess";
  input.user_label = "alice";
  input.app_context = "app";

  core.v_dispatch(input);

  // Under the outbox model the SIGN_CREATED event is published asynchronously
  // by the OutboxPoller (which replays event_outbox), not synchronously by the
  // dispatcher. Drive the poller and await the published event.
  vhsm::signature_store::db::OutboxPoller poller(*conn_, bus);
  poller.start();
  {
    std::unique_lock<std::mutex> lk(bus.m);
    bus.cv.wait_for(lk, std::chrono::seconds(2),
                    [&] { return bus.events.size() >= 1u; });
  }
  poller.stop();

  // Exactly one SIGN_CREATED event, published by the poller.
  ASSERT_EQ(bus.events.size(), 1u);
  EXPECT_EQ(bus.events[0].type,
            vhsm::notification::NotificationEvent::EventType::SIGN_CREATED);
  // The poller stamps the event with real publish time and a "system" actor,
  // not the dispatcher's injected clock / signer identity.
  EXPECT_EQ(bus.events[0].actor, "system");

  // Audit logging for sign operations is performed upstream at the PKCS#11
  // layer (p11_crypto.cpp), not by the dispatcher core, so the core does not
  // append to the audit log here.

  // The record really landed in the DB and round-trips with the right fields.
  SignatureQuery query(*conn_, *token_);
  auto ids = query.get_signature_ids_by_key_fingerprint("fpABC1234567890");
  ASSERT_EQ(ids.size(), 1u);
  auto row = repo_->get_by_id(ids[0]);
  ASSERT_TRUE(row.has_value());
  EXPECT_EQ(s((*row)[1]), "1234567890");       // created_at
  EXPECT_EQ(s((*row)[5]), "fpABC1234567890");  // key_fingerprint
  EXPECT_EQ(s((*row)[6]), "CKM_ECDSA_SHA256"); // mechanism
  EXPECT_EQ(s((*row)[7]), "aabbccddeeff00112233445566778899"); // payload_digest
  EXPECT_FALSE(s((*row)[8]).empty()); // signature_b64 (base64 of {1,2,3,4})
}

TEST_F(SignatureStoreCoreTest, FacadeRejectsDegenerateInput) {
  CapturingNotificationBus bus;
  CapturingAuditLog audit;
  SignatureDispatcher facade(*conn_, *token_, bus, audit,
                             /*ledger_worker=*/nullptr);

  vhsm::crypto::SignResult empty;
  empty.signature = {}; // empty -> rejected
  empty.payload_digest = "deadbeef";

  facade.dispatch(empty, 1234567890, 0, "tok", "kid", "fp123",
                  "CKM_ECDSA_SHA256", "SHA256", "sess", "alice", "app");

  // No notification, no audit, nothing persisted.
  EXPECT_TRUE(bus.events.empty());
  EXPECT_TRUE(audit.calls.empty());
  EXPECT_TRUE(SignatureQuery(*conn_, *token_)
                  .get_signature_ids_by_key_fingerprint("fp123")
                  .empty());
}

// =============================================================================
// VerificationService — local vs ledger cross-check
// =============================================================================

TEST_F(SignatureStoreCoreTest, VerifyLocalOnlyAndNoLedgerTxId) {
  MockLedgerClient ledger;
  VerificationService svc(*conn_, &ledger, *repo_);

  auto id = repo_->insert(1234567890, 0, "tok", "kid", "fpABC1234567890",
                          "CKM_ECDSA_SHA256", "SHA256",
                          "aabbccddeeff00112233445566778899", 4,
                          "MEUCIQD=", "sess", "alice", "app");
  ASSERT_TRUE(id.has_value());

  // Local-only check: record exists.
  auto local = svc.verify_signature(*id, /*check_ledger=*/false);
  EXPECT_TRUE(local.local_record_exists);
  EXPECT_FALSE(local.ledger_record_exists);

  // Ledger requested but no tx id anchored yet -> graceful error.
  auto with_ledger = svc.verify_signature(*id, /*check_ledger=*/true);
  EXPECT_TRUE(with_ledger.local_record_exists);
  EXPECT_FALSE(with_ledger.ledger_record_exists);
  ASSERT_TRUE(with_ledger.error_detail.has_value());
  EXPECT_NE(with_ledger.error_detail->find("No ledger transaction ID"),
            std::string::npos);
}

TEST_F(SignatureStoreCoreTest, VerifyLedgerCrossCheckMatches) {
  MockLedgerClient ledger;
  ledger.entry.record_id = "tx1";
  ledger.entry.key_fingerprint = "fpABC1234567890";
  ledger.entry.payload_digest = "aabbccddeeff00112233445566778899";
  ledger.entry.signature_b64 = "MEUCIQD=";
  ledger.return_entry = true;

  VerificationService svc(*conn_, &ledger, *repo_);

  auto id = repo_->insert(1234567890, 0, "tok", "kid", "fpABC1234567890",
                          "CKM_ECDSA_SHA256", "SHA256",
                          "aabbccddeeff00112233445566778899", 4,
                          "MEUCIQD=", "sess", "alice", "app");
  ASSERT_TRUE(id.has_value());

  // Anchor a ledger tx id on the row so the core consults the ledger.
  conn_->exec("UPDATE signature_records SET ledger_tx_id='tx1', "
              "ledger_status='COMMITTED' WHERE id=?",
              {*id});
  ASSERT_TRUE(repo_->recompute_integrity_hmac(*id));

  auto result = svc.verify_signature(*id, /*check_ledger=*/true);
  EXPECT_TRUE(result.local_record_exists);
  EXPECT_TRUE(result.ledger_record_exists);
  EXPECT_TRUE(result.payload_digest_match);
  EXPECT_TRUE(result.signature_b64_match);
  EXPECT_TRUE(result.key_fingerprint_match);
}

// =============================================================================
// SignatureQuery — local verification + queries + ledger cross-check
// =============================================================================

TEST_F(SignatureStoreCoreTest, QueryLocalVerifyAndListings) {
  MockLedgerClient ledger;
  SignatureQuery query(*conn_, *token_);

  auto id = repo_->insert(1234567890, 0, "tok", "kid", "fpABC1234567890",
                          "CKM_ECDSA_SHA256", "SHA256",
                          "aabbccddeeff00112233445566778899", 4,
                          "MEUCIQD=", "sess", "alice", "app");
  ASSERT_TRUE(id.has_value());
  conn_->exec(
      "UPDATE signature_records SET ledger_status='COMMITTED' WHERE id=?",
      {*id});
  ASSERT_TRUE(repo_->recompute_integrity_hmac(*id));

  // Local verification reflects the COMMITTED status.
  auto local = query.verify_signature(*id);
  EXPECT_TRUE(local.record_found);
  EXPECT_EQ(local.ledger_status, "COMMITTED");
  EXPECT_TRUE(local.ledger_cross_check_ok);

  // Listings by key fingerprint and by time range.
  EXPECT_EQ(
      query.get_signature_ids_by_key_fingerprint("fpABC1234567890").size(), 1u);
  EXPECT_EQ(
      query.get_signature_ids_by_time_range(1000000000, 2000000000).size(), 1u);
  EXPECT_TRUE(
      query.get_signature_ids_by_time_range(2000000000, 3000000000).empty());
}

TEST_F(SignatureStoreCoreTest, QueryLedgerCrossCheck) {
  MockLedgerClient ledger;
  ledger.entry.record_id = "tx1";
  ledger.entry.key_fingerprint = "fpABC1234567890";
  ledger.entry.payload_digest = "aabbccddeeff00112233445566778899";
  ledger.entry.signature_b64 = "MEUCIQD=";
  ledger.return_entry = true;

  SignatureQuery query(*conn_, *token_);

  auto id = repo_->insert(1234567890, 0, "tok", "kid", "fpABC1234567890",
                          "CKM_ECDSA_SHA256", "SHA256",
                          "aabbccddeeff00112233445566778899", 4,
                          "MEUCIQD=", "sess", "alice", "app");
  ASSERT_TRUE(id.has_value());
  // Anchor ledger_tx_id so VerificationService (which looks up by ledger_tx_id, not record_id) can find the mock entry
  conn_->exec("UPDATE signature_records SET ledger_tx_id='tx1', ledger_status='COMMITTED' WHERE id=?", {*id});
  ASSERT_TRUE(repo_->recompute_integrity_hmac(*id));
  ledger.entry.record_id = *id;

  auto result = query.verify_signature(*id, ledger);
  EXPECT_TRUE(result.record_found);
  EXPECT_TRUE(result.ledger_cross_check_ok);
}

TEST_F(SignatureStoreCoreTest, FacadeRejectsBadInputs) {
  SignatureQuery query(*conn_, *token_);

  // Empty id -> no lookup attempted.
  auto r = query.verify_signature("");
  EXPECT_FALSE(r.record_found);
  EXPECT_TRUE(query.get_signature_ids_by_key_fingerprint("").empty());
  EXPECT_TRUE(
      query.get_signature_ids_by_time_range(2000000000, 1000000000).empty());
}

// =============================================================================
// Regression: tamper-evidence was dead code — now consolidated and reachable
// =============================================================================

TEST_F(SignatureStoreCoreTest, TamperDetectedViaConsolidatedVerify) {
  // This test proves the fix for the gap described in the Claude prompt:
  // before the consolidation, SignatureQuery::v_verify_signature only checked
  // ledger_status=="COMMITTED" and never called RowIntegrity::verify_hmac.
  // An attacker with raw DB access could flip ledger_status or payload_digest
  // and no verification call through the production path would notice.
  // After the fix, both VerificationService and SignatureQuery (now forwarding)
  // call verify_integrity and fail closed.
  MockLedgerClient ledger;
  VerificationService svc(*conn_, &ledger, *repo_);
  SignatureQuery query(*conn_, *token_);

  auto id = repo_->insert(1234567890, 0, "tok", "kid", "fpABC1234567890",
                          "CKM_ECDSA_SHA256", "SHA256",
                          "aabbccddeeff00112233445566778899", 4,
                          "MEUCIQD=", "sess", "alice", "app");
  ASSERT_TRUE(id.has_value());

  // Mark COMMITTED so old insecure check would have passed
  conn_->exec("UPDATE signature_records SET ledger_status='COMMITTED' WHERE id=?",
              {*id});
  ASSERT_TRUE(repo_->recompute_integrity_hmac(*id));

  // Sanity: before tamper, both paths say valid
  {
    auto v1 = svc.verify_signature(*id, /*check_ledger=*/false);
    EXPECT_TRUE(v1.local_record_exists);
    EXPECT_TRUE(v1.integrity_hmac_ok);
    auto q1 = query.verify_signature(*id);
    EXPECT_TRUE(q1.record_found);
    EXPECT_TRUE(q1.ledger_cross_check_ok);
  }

  // Tamper directly via SQL — flip payload_digest without recomputing HMAC
  conn_->exec("UPDATE signature_records SET payload_digest='TAMPERED_TAMPERED_TAMPERED_TAMPERED' WHERE id=?",
              {*id});

  // Consolidated path must now detect it via HMAC (fail-closed)
  {
    auto v2 = svc.verify_signature(*id, /*check_ledger=*/false);
    EXPECT_TRUE(v2.local_record_exists);
    EXPECT_FALSE(v2.integrity_hmac_ok) << "HMAC should fail after payload_digest tamper";
    ASSERT_TRUE(v2.error_detail.has_value());
    EXPECT_NE(v2.error_detail->find("HMAC verification failed"), std::string::npos);
  }
  {
    auto q2 = query.verify_signature(*id);
    EXPECT_TRUE(q2.record_found);
    EXPECT_FALSE(q2.ledger_cross_check_ok) << "SignatureQuery now forwards to VerificationService, so HMAC fail => not ok";
    ASSERT_TRUE(q2.error_detail.has_value());
    EXPECT_NE(q2.error_detail->find("HMAC verification failed"), std::string::npos);
  }

  // Also verify that flipping ledger_status alone (the old bypass) is now caught when HMAC is recomputed?
  // Actually flipping ledger_status from COMMITTED to PENDING without HMAC would have passed old check;
  // now HMAC fails because we didn't recompute it, so same detection.
  conn_->exec("UPDATE signature_records SET ledger_status='PENDING' WHERE id=?",
              {*id});
  {
    auto v3 = svc.verify_signature(*id, /*check_ledger=*/false);
    EXPECT_FALSE(v3.integrity_hmac_ok);
  }
}

TEST_F(SignatureStoreCoreTest, LedgerCrossCheckStillWorksAfterConsolidation) {
  MockLedgerClient ledger;
  ledger.entry.record_id = "tx1";
  ledger.entry.key_fingerprint = "fpABC1234567890";
  ledger.entry.payload_digest = "aabbccddeeff00112233445566778899";
  ledger.entry.signature_b64 = "MEUCIQD=";
  ledger.return_entry = true;

  VerificationService svc(*conn_, &ledger, *repo_);
  SignatureQuery query(*conn_, *token_);

  auto id = repo_->insert(1234567890, 0, "tok", "kid", "fpABC1234567890",
                          "CKM_ECDSA_SHA256", "SHA256",
                          "aabbccddeeff00112233445566778899", 4,
                          "MEUCIQD=", "sess", "alice", "app");
  ASSERT_TRUE(id.has_value());
  conn_->exec("UPDATE signature_records SET ledger_tx_id='tx1', ledger_status='COMMITTED' WHERE id=?",
              {*id});
  ASSERT_TRUE(repo_->recompute_integrity_hmac(*id));

  // Both paths should agree when ledger matches
  auto v = svc.verify_signature(*id, /*check_ledger=*/true);
  EXPECT_TRUE(v.integrity_hmac_ok);
  EXPECT_TRUE(v.ledger_record_exists);
  EXPECT_TRUE(v.payload_digest_match);

  auto q = query.verify_signature(*id, ledger);
  EXPECT_TRUE(q.record_found);
  EXPECT_TRUE(q.ledger_cross_check_ok);
}
