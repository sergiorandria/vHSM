// signature_store_integration_test.cpp — Integration tests that exercise the
// signature store end-to-end: file-backed SQLite persistence, schema
// idempotency across re-opens, the full dispatch → database flow, and the
// LedgerWorker commit callback that stamps COMMITTED ledger fields back onto
// the persisted record.
//
// Unlike the unit tests (which use ":memory:"), these tests use a real binary
// file on disk so data persists across connection open/close cycles — the same
// durability the PKCS#11 module relies on.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "../../../src/signature_store/db_connection.h"
#include "../../../src/signature_store/db_schema.h"
#include "../../../src/signature_store/signature_dispatcher.h"
#include "../../../src/signature_store/signature_query.h"
#include "../../../src/signature_store/signature_repository.h"
#include "../../../src/signature_store/sqlite_connection.h"

#include "../../../src/audit/audit_log.h"
#include "../../../src/core/types.h"
#include "../../../src/keystore/token.h"
#include "../../../src/ledger/ledger_client.h"
#include "../../../src/ledger/ledger_entry.h"
#include "../../../src/ledger/ledger_worker.h"
#include "../../../src/notification/notification_bus.h"
#include "../../../src/notification/notification_event.h"

using namespace vhsm::signature_store;
using namespace vhsm::signature_store::db;

namespace {

std::string s(const std::optional<std::string> &opt) {
  return opt ? *opt : "<NULL>";
}

// Test doubles -------------------------------------------------------------

class CapturingNotificationBus : public vhsm::notification::NotificationBus {
public:
  void publish(const vhsm::notification::NotificationEvent &e) override {
    std::lock_guard<std::mutex> lock(m);
    events.push_back(e);
    cv.notify_all();
  }
  std::vector<vhsm::notification::NotificationEvent> events;
  std::mutex m;
  std::condition_variable cv;
};

class CapturingAuditLog : public vhsm::audit::AuditLog {
public:
  void append(const std::string &id, const std::string &type) override {
    calls.push_back({id, type});
  }
  struct Call {
    std::string id;
    std::string type;
  };
  std::vector<Call> calls;
};

// A LedgerClient that always "commits" immediately with a canned entry.
class MockLedgerClient : public vhsm::ledger::LedgerClient {
public:
  MockLedgerClient() = default;

  std::optional<vhsm::ledger::LedgerEntry>
  submit_record(const SignatureRecord &rec) override {
    ++submit_count;
    last_record = rec;
    return response;
  }

  std::optional<vhsm::ledger::LedgerEntry>
  get_record(const std::string &) override {
    return std::nullopt;
  }

  vhsm::ledger::LedgerEntry
      response;                // what the worker will stamp on the record
  SignatureRecord last_record; // the record we were asked to anchor
  std::atomic<int> submit_count{0};
};

// Fixture ------------------------------------------------------------------

// Every test gets a unique file path under the temp dir so parallel test
// execution cannot clobber another test's database file.
class SignatureStoreIntegrationTest : public ::testing::Test {
protected:
  void SetUp() override {
    std::filesystem::path dir = std::filesystem::temp_directory_path();
    dir /= "vhsm_integration_" +
           std::to_string(
               std::chrono::steady_clock::now().time_since_epoch().count());
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    db_path_ = (dir / "vhsm.sqlite").string();
  }

  void TearDown() override {
    conn_.reset();
    std::error_code ec;
    std::filesystem::remove_all(std::filesystem::path(db_path_).parent_path(),
                                ec);
  }

  // Opens (creating if needed) a file-backed connection + bootstrapped schema.
  void open_db() {
    conn_ = make_sqlite_connection(db_path_);
    schema_ = std::make_unique<DbSchema>(*conn_);
    schema_->bootstrap();
    token_ = std::make_unique<vhsm::keystore::Token>("int-token", "int-id");
    repo_ = std::make_unique<SignatureRepository>(*conn_, *token_);
  }

  std::optional<std::string> insert_dummy_record(const std::string &key_fp) {
    return repo_->insert(1234567890, 0, "int-token", "key-" + key_fp, key_fp,
                         "CKM_ECDSA_SHA256", "SHA256",
                         "aabbccddeeff00112233445566778899", 4, "MEUCIQD...",
                         "sess1", "alice", "caller-app");
  }

  std::string db_path_;
  std::unique_ptr<IDbConnection> conn_;
  std::unique_ptr<DbSchema> schema_;
  std::unique_ptr<vhsm::keystore::Token> token_;
  std::unique_ptr<SignatureRepository> repo_;
};

} // namespace

// ===========================================================================
// File-backed persistence across connection open/close cycles
// ===========================================================================

TEST_F(SignatureStoreIntegrationTest, SignaturePersistsAcrossReopen) {
  open_db();
  ASSERT_TRUE(conn_ != nullptr);

  // The connection is truly file-backed (not ":memory:").
  EXPECT_NE(db_path_, ":memory:");
  EXPECT_TRUE(std::filesystem::exists(db_path_));

  auto id1 = insert_dummy_record("fpAAA");
  auto id2 = insert_dummy_record("fpBBB");
  ASSERT_TRUE(id1.has_value());
  ASSERT_TRUE(id2.has_value());
  EXPECT_NE(*id1, *id2);

  // Close the file-backed connection (simulates module unload).
  conn_.reset();
  schema_.reset();
  repo_.reset();

  // Re-open the same file (simulates C_Initialize after C_Finalize): the
  // records must still be there — they were durably committed.
  open_db();
  auto row = repo_->get_by_id(*id1);
  ASSERT_TRUE(row.has_value());
  EXPECT_EQ(s((*row)[0]), *id1);               // id
  EXPECT_EQ(s((*row)[1]), "1234567890");       // created_at
  EXPECT_EQ(s((*row)[5]), "fpAAA");            // key_fingerprint
  EXPECT_EQ(s((*row)[6]), "CKM_ECDSA_SHA256"); // mechanism
  EXPECT_EQ(s((*row)[7]), "aabbccddeeff00112233445566778899"); // payload_digest
  EXPECT_EQ(s((*row)[10]), "alice");                           // user_label

  auto row2 = repo_->get_by_id(*id2);
  ASSERT_TRUE(row2.has_value());
  EXPECT_EQ(s((*row2)[5]), "fpBBB");
}

TEST_F(SignatureStoreIntegrationTest,
       SchemaIsIdempotentOnReopenAndVerifyHolds) {
  open_db();
  auto id = insert_dummy_record("fpCCC");
  ASSERT_TRUE(id.has_value());

  // Closing the connection and bootstrapping again must be a no-op-safe
  // migration (CREATE IF NOT EXISTS); it must not reset or wipe data.
  conn_.reset();
  schema_.reset();
  repo_.reset();

  open_db(); // bootstrap() on an existing DB at current version

  auto row = repo_->get_by_id(*id);
  ASSERT_TRUE(row.has_value());
  EXPECT_EQ(s((*row)[5]), "fpCCC");

  // The canonical schema is intact after the second bootstrap.
  std::string err;
  EXPECT_TRUE(schema_->verify_schema(err)) << err;
}

// ===========================================================================
// Dispatch → DB with file-backed persistence + ledger worker plumbing
// ===========================================================================

TEST_F(SignatureStoreIntegrationTest,
       DispatchPersistsAndLedgerWorkerAnchorsIt) {
  open_db();

  CapturingNotificationBus bus;
  CapturingAuditLog audit;
  MockLedgerClient ledger;
  ledger.response.record_id = "fpAAA";
  ledger.response.key_fingerprint = "fpAAA";
  ledger.response.payload_digest = "aabbccddeeff00112233445566778899";
  ledger.response.signature_b64 = "MEUCIQD...";
  ledger.response.created_at = 1234567890;
  ledger.response.tx_id = "tx-1234-5678";
  ledger.response.block_number = 42;

  // Commit callback mirrors what p11_init.cpp registers: it stamps the
  // LedgerEntry back onto the persisted signature record.
  std::mutex cb_m;
  std::condition_variable cb_cv;
  std::vector<std::string> anchored_ids;
  int callback_count = 0;
  bool db_update_ok = false;

  std::unique_ptr<vhsm::ledger::LedgerWorker> worker;
  {
    auto *db = conn_.get();
    auto *tok = token_.get();
    worker = std::make_unique<vhsm::ledger::LedgerWorker>(
        ledger, bus,
        [db, tok, &cb_m, &cb_cv, &anchored_ids, &callback_count,
         &db_update_ok](const SignatureRecord &rec,
                        const vhsm::ledger::LedgerEntry &entry) {
          {
            std::lock_guard<std::mutex> lock(cb_m);
            anchored_ids.push_back(rec.record_id);
            ++callback_count;
          }
          SignatureRepository repo(*db, *tok);
          bool ok = repo.update_ledger_fields(rec.record_id, entry);
          {
            std::lock_guard<std::mutex> lock(cb_m);
            db_update_ok = ok;
          }
          cb_cv.notify_all();
        });
  }
  worker->start();

  SignatureDispatcher dispatcher(*conn_, *token_, bus, audit, worker.get());

  vhsm::crypto::SignResult sign_result;
  sign_result.signature = {0x01, 0x02, 0x03, 0x04};
  sign_result.mechanism_str = "CKM_ECDSA_SHA256";
  sign_result.digest_alg = "SHA256";
  sign_result.payload_digest = "aabbccddeeff00112233445566778899";
  sign_result.payload_size = 4;

  bool ok = dispatcher.dispatch(sign_result,
                                1234567890,  // created_at
                                0,           // slot_id
                                "int-token", // token_label
                                "key-fpAAA", // key_id
                                "fpAAA",     // key_fingerprint
                                "CKM_ECDSA_SHA256", "SHA256", "sess1", "alice",
                                "caller-app");
  ASSERT_TRUE(ok);

  // The record was persisted by the dispatcher.
  SignatureQuery query(*conn_, *token_);
  auto ids = query.get_signature_ids_by_key_fingerprint("fpAAA");
  ASSERT_EQ(ids.size(), 1u);
  const std::string &record_id = ids[0];

  // Wait (up to 5s) for the ledger worker thread to commit + invoke callback.
  {
    std::unique_lock<std::mutex> lk(cb_m);
    ASSERT_TRUE(cb_cv.wait_for(lk, std::chrono::seconds(5),
                               [&] { return callback_count > 0; }));
  }
  EXPECT_EQ(callback_count, 1);
  ASSERT_EQ(anchored_ids.size(), 1u);
  EXPECT_EQ(anchored_ids[0], record_id);
  EXPECT_TRUE(db_update_ok);

  // The worker asked the client to submit exactly the record we dispatched.
  EXPECT_EQ(ledger.submit_count, 1);
  EXPECT_EQ(ledger.last_record.record_id, record_id);
  EXPECT_EQ(ledger.last_record.user_label, std::optional<std::string>("alice"));

  // The commit callback stamped the ledger fields onto the record:
  // ledger_status transitions PENDING → COMMITTED.
  auto row = repo_->get_by_id(record_id);
  ASSERT_TRUE(row.has_value());
  EXPECT_EQ(s((*row)[0]), record_id);
  EXPECT_EQ(s((*row)[12]), "tx-1234-5678"); // ledger_tx_id
  EXPECT_EQ(s((*row)[13]), "42");           // ledger_block_num
  EXPECT_EQ(s((*row)[17]), "COMMITTED");    // ledger_status

  // And a LEDGER_COMMITTED notification was published on the bus.
  bool saw_committed = false;
  {
    std::lock_guard<std::mutex> lk(bus.m);
    for (const auto &e : bus.events) {
      if (e.type == vhsm::notification::NotificationEvent::EventType::
                        LEDGER_COMMITTED &&
          e.summary.find(record_id) != std::string::npos) {
        saw_committed = true;
        break;
      }
    }
  }
  EXPECT_TRUE(saw_committed);

  worker->drain_and_stop();
  worker.reset();

  // Re-open the DB: the record (now COMMITTED) persists with its ledger proof.
  conn_.reset();
  schema_.reset();
  repo_.reset();
  open_db();
  auto reopened = repo_->get_by_id(record_id);
  ASSERT_TRUE(reopened.has_value());
  EXPECT_EQ(s((*reopened)[12]), "tx-1234-5678");
  EXPECT_EQ(s((*reopened)[13]), "42");
  EXPECT_EQ(s((*reopened)[17]), "COMMITTED");
}

// A worker with no commit callback still publishes LEDGER_COMMITTED but never
// touches the DB (the callback is what stamps the ledger fields). This is the
// local-only wiring whenever a Fabric gateway is not configured.
TEST_F(SignatureStoreIntegrationTest,
       LedgerWorkerWithoutCallbackPublishesOnly) {
  open_db();

  CapturingNotificationBus bus;
  MockLedgerClient ledger;
  ledger.response.tx_id = "tx-deferred";
  ledger.response.block_number = 7;

  vhsm::ledger::LedgerWorker worker(ledger, bus, /*on_committed=*/nullptr);
  worker.start();

  SignatureRecord rec;
  rec.record_id = "rec-deferred-0001";
  rec.created_at = 1234567890;
  rec.slot_id = 0;
  rec.token_label = "int-token";
  rec.key_id = "key-fpDDD";
  rec.key_fingerprint = "fpDDD";
  rec.mechanism = "CKM_ECDSA_SHA256";
  rec.digest_algorithm = "SHA256";
  rec.payload_digest = "deadbeefdeadbeefdeadbeefdeadbeef";
  rec.signature_b64 = "MEUCIQD...";
  rec.payload_size = 4;
  rec.session_handle = "sess1";
  rec.user_label = "bob";
  rec.ledger_status = "PENDING";

  worker.submit_record(rec);
  worker.drain_and_stop();

  EXPECT_EQ(ledger.submit_count, 1);

  bool saw_committed = false;
  {
    std::lock_guard<std::mutex> lk(bus.m);
    for (const auto &e : bus.events) {
      if (e.type ==
          vhsm::notification::NotificationEvent::EventType::LEDGER_COMMITTED) {
        if (e.summary.find("rec-deferred-0001") != std::string::npos) {
          saw_committed = true;
        }
      }
    }
  }
  EXPECT_TRUE(saw_committed);

  // The pending record remains PENDING in the DB since no callback stamped it.
  auto id = insert_dummy_record("fpDDD");
  ASSERT_TRUE(id.has_value());
  auto row = repo_->get_by_id(*id);
  ASSERT_TRUE(row.has_value());
  EXPECT_EQ(s((*row)[17]), "PENDING");
}