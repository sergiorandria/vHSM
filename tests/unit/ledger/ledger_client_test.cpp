// ledger_client_test.cpp — Unit tests for LedgerClient and the LedgerWorker's
// interaction with it.
//
// LedgerClient wraps the concrete Fabric Gateway SDK; it cannot be exercised
// against a real peer here (that is the job of integration/ledger/).  These
// tests cover the client's fail-closed construction contract and the worker's
// consuming of the client through a mock seam (both client methods are virtual
// and the class offers a protected default ctor for test doubles).

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "ledger_client.h"
#include "ledger_entry.h"
#include "ledger_worker.h"

#include "../../../src/notification/bounded_notification_bus.h"
#include "../../../src/notification/notification_bus.h"
#include "../../../src/notification/notification_event.h"

using vhsm::ledger::LedgerClient;
using vhsm::ledger::LedgerEntry;
using vhsm::ledger::LedgerWorker;
using vhsm::ledger::RetryPolicy;
using vhsm::notification::BoundedNotificationBus;
using vhsm::notification::NotificationBus;
using vhsm::notification::NotificationEvent;

namespace {

SignatureRecord make_record(const std::string &id = "rec-1") {
  SignatureRecord r;
  r.record_id = id;
  r.created_at = 1700000000000;
  r.slot_id = 0;
  r.token_label = "TestToken";
  r.key_id = "key-1";
  r.key_fingerprint = "fingerprint-of-key-1";
  r.mechanism = "CKM_ECDSA_SHA256";
  r.digest_algorithm = "SHA-256";
  r.payload_digest = "deadbeef";
  r.signature_b64 = "c2lnbmF0dXJl"; // "signature"
  r.payload_size = 32;
  r.session_handle = "session-1";
  r.ledger_status = "PENDING";
  return r;
}

// A recording mock client whose failure behaviour is scripted per test.
class MockLedgerClient : public LedgerClient {
public:
  int submit_calls = 0;
  int get_calls = 0;
  int fail_submits = 0; // submit fails this many times before succeeding
  std::vector<SignatureRecord> submitted;
  std::optional<LedgerEntry> fake_entry;

  explicit MockLedgerClient(std::optional<LedgerEntry> entry = std::nullopt)
      : fake_entry(std::move(entry)) {}

  std::optional<LedgerEntry> submit_record(const SignatureRecord &record) override {
    ++submit_calls;
    submitted.push_back(record);
    if (fail_submits > 0) {
      --fail_submits;
      return std::nullopt;
    }
    if (fake_entry) {
      return fake_entry;
    }
    LedgerEntry e;
    e.record_id = record.record_id;
    e.key_fingerprint = record.key_fingerprint;
    e.payload_digest = record.payload_digest;
    e.signature_b64 = record.signature_b64;
    e.created_at = record.created_at;
    e.tx_id = "tx-" + record.record_id;
    e.block_number = 42;
    return e;
  }

  std::optional<LedgerEntry> get_record(const std::string &record_id) override {
    ++get_calls;
    if (!fake_entry) {
      return std::nullopt;
    }
    auto e = *fake_entry;
    e.record_id = record_id;
    return e;
  }
};

// Recording notification bus that keeps a copy of every published event.
class RecordingBus : public NotificationBus {
public:
  std::vector<NotificationEvent> events;
  void publish(const NotificationEvent &event) override { events.push_back(event); }
};

NotificationEvent last_of_type(const RecordingBus &bus,
                               NotificationEvent::EventType type) {
  for (auto it = bus.events.rbegin(); it != bus.events.rend(); ++it) {
    if (it->type == type)
      return *it;
  }
  return NotificationEvent{};
}

// ---------------------------------------------------------------------------
// LedgerClient construction contract
// ---------------------------------------------------------------------------

TEST(LedgerClientTest, ConstructorRejectsMissingCertificateMaterials) {
  // Fail-closed: no identity certificate/key must throw rather than create a
  // channel that would silently downgrade to unauthenticated transport.
  EXPECT_THROW(LedgerClient("localhost:7053", "", ""), std::runtime_error);
  EXPECT_THROW(LedgerClient("localhost:7053", "cert.pem", ""),
               std::runtime_error);
  EXPECT_THROW(LedgerClient("localhost:7053", "", "key.pem"),
               std::runtime_error);
}

TEST(LedgerClientTest, ConstructorRejectsUnreadableCertificateFile) {
  // A configured-but-missing file is a configuration error: loadFile throws,
  // and the constructor must propagate it (no partial channel left behind).
  EXPECT_THROW(LedgerClient("localhost:7053", "/nonexistent/cert.pem",
                            "/nonexistent/key.pem"),
               std::runtime_error);
}

// ---------------------------------------------------------------------------
// LedgerWorker: commit flow & callbacks
// ---------------------------------------------------------------------------

TEST(LedgerWorkerTest, SubmitCommitsAndInvokesCallback) {
  RecordingBus bus;
  MockLedgerClient client;
  bool callback_called = false;
  LedgerEntry callback_entry;
  {
    LedgerWorker worker(client, bus,
                        [&](const SignatureRecord &, const LedgerEntry &e) {
                          callback_called = true;
                          callback_entry = e;
                        });
    worker.start();

    auto rec = make_record("rec-commit-1");
    worker.submit_record(rec);

    // Wait for the async commit to complete.
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!callback_called && std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    worker.drain_and_stop();
  }

  EXPECT_TRUE(callback_called);
  EXPECT_EQ(client.submit_calls, 1);
  EXPECT_EQ(callback_entry.record_id, "rec-commit-1");
  EXPECT_EQ(callback_entry.tx_id, "tx-rec-commit-1");
  EXPECT_EQ(callback_entry.block_number, 42);
}

TEST(LedgerWorkerTest, PublishesCommittedEventOnSuccess) {
  RecordingBus bus;
  MockLedgerClient client;
  {
    LedgerWorker worker(client, bus);
    worker.start();
    worker.submit_record(make_record("rec-event-1"));
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    bool found = false;
    while (std::chrono::steady_clock::now() < deadline) {
      if (last_of_type(bus, NotificationEvent::EventType::LEDGER_COMMITTED)
              .timestamp != 0) {
        found = true;
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    worker.drain_and_stop();
    EXPECT_TRUE(found);
    const auto ev = last_of_type(bus, NotificationEvent::EventType::LEDGER_COMMITTED);
    EXPECT_EQ(ev.source, "LedgerWorker");
    EXPECT_EQ(ev.severity, NotificationEvent::Severity::INFO);
  }
}

TEST(LedgerWorkerTest, FailsAndPublishesFailureEvent) {
  RecordingBus bus;
  MockLedgerClient client;
  client.fail_submits = 1000; // always fail

  int attempts = 0;
  RetryPolicy policy;
  policy.max_retries = 2;   // 2 retries beyond the first attempt
  policy.base_delay_ms = 1; // fast backoff for the test
  policy.max_delay_ms = 5;
  policy.delay_multiplier = 2;

  {
    LedgerWorker worker(client, bus, nullptr, policy);
    worker.start();
    worker.submit_record(make_record("rec-fail-1"));
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    // Wait until the failure event is published.
    bool found = false;
    while (std::chrono::steady_clock::now() < deadline) {
      if (last_of_type(bus, NotificationEvent::EventType::LEDGER_COMMIT_FAILED)
              .timestamp != 0) {
        found = true;
        attempts = client.submit_calls;
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    worker.drain_and_stop();
    EXPECT_TRUE(found);
    // First attempt + max_retries retries → 3 submit attempts.
    EXPECT_EQ(attempts, 1 + policy.max_retries);
    const auto ev =
        last_of_type(bus, NotificationEvent::EventType::LEDGER_COMMIT_FAILED);
    EXPECT_EQ(ev.severity, NotificationEvent::Severity::WARNING);
    EXPECT_EQ(ev.source, "LedgerWorker");
  }
}

TEST(LedgerWorkerTest, RetriesTransientFailureThenSucceeds) {
  RecordingBus bus;
  MockLedgerClient client;
  client.fail_submits = 2; // fail twice, then commit

  int callback_count = 0;
  RetryPolicy policy;
  policy.max_retries = 5;
  policy.base_delay_ms = 1;
  policy.max_delay_ms = 5;
  policy.delay_multiplier = 2;

  {
    LedgerWorker worker(client, bus,
                        [&](const SignatureRecord &, const LedgerEntry &) {
                          ++callback_count;
                        },
                        policy);
    worker.start();
    worker.submit_record(make_record("rec-transient"));
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
      if (callback_count > 0)
        break;
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    worker.drain_and_stop();
  }

  EXPECT_EQ(callback_count, 1);
  EXPECT_EQ(client.submit_calls, 3); // 2 failures + 1 success
}

TEST(LedgerWorkerTest, SubmissionsSurviveDrainInFlight) {
  // Simulate a worker with slow submissions: drain_and_stop must wait for the
  // in-flight submission to finish (never abandon it or leak the callback).
  RecordingBus bus;
  MockLedgerClient client;

  std::atomic<int> callback_count{0};
  bool callback_called = false;
  {
    LedgerWorker worker(client, bus,
                        [&](const SignatureRecord &, const LedgerEntry &) {
                          callback_called = true;
                          ++callback_count;
                        });
    worker.start();
    // Do not wait: submit then immediately drain; the pool drains in-flight
    // tasks on shutdown.
    worker.submit_record(make_record("rec-drain"));
    worker.drain_and_stop();
    // Give the pool a beat to run the task that was in flight (it is
    // guaranteed to have run) — callback must have fired.
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    EXPECT_TRUE(callback_called);
  }
}

} // namespace