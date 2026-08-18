// signature_store_core_test.cpp — Unit tests for the signature_store internal
// cores (dispatcher / verification / query) and their validating facades.
//
// The cores are exercised directly where they own injectable dependencies
// (clock, notification bus, audit log, ledger client); the facades are exercised
// for input validation.

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "../../../src/signature_store/sqlite_connection.h"
#include "../../../src/signature_store/db_connection.h"
#include "../../../src/signature_store/signature_repository.h"
#include "../../../src/signature_store/db_schema.h"
#include "../../../src/keystore/token.h"

#include "../../../src/core/types.h"
#include "../../../src/core/hsm_clock.h"

#include "../../../src/signature_store/signature_dispatcher.h"
#include "../../../src/signature_store/verification_service.h"
#include "../../../src/signature_store/signature_query.h"

#include "../../../src/signature_store/internal/signature_dispatcher_core.h"
#include "../../../src/signature_store/internal/verification_service_core.h"
#include "../../../src/signature_store/internal/signature_query_core.h"

#include "../../../src/notification/notification_bus.h"
#include "../../../src/notification/notification_event.h"
#include "../../../src/audit/audit_log.h"
#include "../../../src/ledger/ledger_client.h"
#include "../../../src/ledger/ledger_entry.h"

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
    void publish(const vhsm::notification::NotificationEvent& e) override {
        events.push_back(e);
    }
    std::vector<vhsm::notification::NotificationEvent> events;
};

class CapturingAuditLog : public vhsm::audit::AuditLog {
public:
    void append(const std::string& id, const std::string& type) override {
        calls.push_back({id, type});
    }
    struct Call { std::string id; std::string type; };
    std::vector<Call> calls;
};

class MockLedgerClient : public vhsm::ledger::LedgerClient {
public:
    MockLedgerClient() : vhsm::ledger::LedgerClient() {}
    std::optional<vhsm::ledger::LedgerEntry> get_record(const std::string&) override {
        if (!return_entry) return std::nullopt;
        return entry;
    }
    vhsm::ledger::LedgerEntry entry;
    bool return_entry = false;
};

// ---- helpers -----------------------------------------------------------------

std::string s(const std::optional<std::string>& opt) {
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

TEST_F(SignatureStoreCoreTest, DispatchInsertsRecordAndStampsEventWithInjectedClock) {
    CapturingNotificationBus bus;
    CapturingAuditLog audit;
    FakeHsmClock clock(1700000000123LL);
    v_SignatureDispatcherCore_M1 core(*conn_, *token_, bus, audit, /*ledger_worker=*/nullptr, clock);

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

    // Exactly one SIGN_CREATED event, stamped with the injected clock.
    ASSERT_EQ(bus.events.size(), 1u);
    EXPECT_EQ(bus.events[0].type,
              vhsm::notification::NotificationEvent::EventType::SIGN_CREATED);
    EXPECT_EQ(bus.events[0].timestamp, 1700000000123LL);
    EXPECT_EQ(bus.events[0].actor, "alice");

    // Audit log received the C_SIGN append.
    ASSERT_EQ(audit.calls.size(), 1u);
    EXPECT_EQ(audit.calls[0].type, "C_SIGN");

    // The record really landed in the DB and round-trips with the right fields.
    SignatureQuery query(*conn_, *token_);
    auto ids = query.get_signature_ids_by_key_fingerprint("fpABC1234567890");
    ASSERT_EQ(ids.size(), 1u);
    auto row = repo_->get_by_id(ids[0]);
    ASSERT_TRUE(row.has_value());
    EXPECT_EQ(s((*row)[1]), "1234567890");          // created_at
    EXPECT_EQ(s((*row)[5]), "fpABC1234567890");     // key_fingerprint
    EXPECT_EQ(s((*row)[6]), "CKM_ECDSA_SHA256");    // mechanism
    EXPECT_EQ(s((*row)[7]), "aabbccddeeff00112233445566778899"); // payload_digest
    EXPECT_FALSE(s((*row)[8]).empty());             // signature_b64 (base64 of {1,2,3,4})
}

TEST_F(SignatureStoreCoreTest, FacadeRejectsDegenerateInput) {
    CapturingNotificationBus bus;
    CapturingAuditLog audit;
    SignatureDispatcher facade(*conn_, *token_, bus, audit, /*ledger_worker=*/nullptr);

    vhsm::crypto::SignResult empty;
    empty.signature = {};  // empty -> rejected
    empty.payload_digest = "deadbeef";

    facade.dispatch(empty, 1234567890, 0, "tok", "kid", "fp123", "CKM_ECDSA_SHA256",
                    "SHA256", "sess", "alice", "app");

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
    VerificationService svc(*conn_, ledger, *repo_);

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
    EXPECT_NE(with_ledger.error_detail->find("No ledger transaction ID"), std::string::npos);
}

TEST_F(SignatureStoreCoreTest, VerifyLedgerCrossCheckMatches) {
    MockLedgerClient ledger;
    ledger.entry.record_id = "tx1";
    ledger.entry.key_fingerprint = "fpABC1234567890";
    ledger.entry.payload_digest = "aabbccddeeff00112233445566778899";
    ledger.entry.signature_b64 = "MEUCIQD=";
    ledger.return_entry = true;

    VerificationService svc(*conn_, ledger, *repo_);

    auto id = repo_->insert(1234567890, 0, "tok", "kid", "fpABC1234567890",
                            "CKM_ECDSA_SHA256", "SHA256",
                            "aabbccddeeff00112233445566778899", 4,
                            "MEUCIQD=", "sess", "alice", "app");
    ASSERT_TRUE(id.has_value());

    // Anchor a ledger tx id on the row so the core consults the ledger.
    conn_->exec("UPDATE signature_records SET ledger_tx_id='tx1', ledger_status='COMMITTED' WHERE id=?",
                {*id});

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
    conn_->exec("UPDATE signature_records SET ledger_status='COMMITTED' WHERE id=?", {*id});

    // Local verification reflects the COMMITTED status.
    auto local = query.verify_signature(*id);
    EXPECT_TRUE(local.record_found);
    EXPECT_EQ(local.ledger_status, "COMMITTED");
    EXPECT_TRUE(local.ledger_cross_check_ok);

    // Listings by key fingerprint and by time range.
    EXPECT_EQ(query.get_signature_ids_by_key_fingerprint("fpABC1234567890").size(), 1u);
    EXPECT_EQ(query.get_signature_ids_by_time_range(1000000000, 2000000000).size(), 1u);
    EXPECT_TRUE(query.get_signature_ids_by_time_range(2000000000, 3000000000).empty());
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
    EXPECT_TRUE(query.get_signature_ids_by_time_range(2000000000, 1000000000).empty());
}
