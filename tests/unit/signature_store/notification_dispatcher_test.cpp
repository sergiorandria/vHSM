// notification_dispatcher_test.cpp — Unit tests for the notification
// dispatcher: channel routing, severity gating, event-type filtering,
// retry/backoff for WARN/CRITICAL, and best-effort INFO delivery.
//
// The dispatcher reads subscribers from the (SQLite-backed) repository, so
// these tests bootstrap the schema on a ":memory:" connection and register real
// subscribers, then drive events through a bounded bus + a fake adapter.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "../../../src/signature_store/db_connection.h"
#include "../../../src/signature_store/db_schema.h"
#include "../../../src/signature_store/notification_dispatcher.h"
#include "../../../src/signature_store/notification_repository.h"

#include "../../../src/notification/bounded_notification_bus.h"
#include "../../../src/notification/notification_adapter.h"
#include "../../../src/notification/notification_bus.h"
#include "../../../src/notification/notification_event.h"

using vhsm::notification::BoundedNotificationBus;
using vhsm::notification::NotificationAdapter;
using vhsm::notification::NotificationEvent;
using vhsm::notification::NotificationSubscriber;
using vhsm::signature_store::db::IDbConnection;
using vhsm::signature_store::db::NotificationDispatcher;
using vhsm::signature_store::db::NotificationRepository;

namespace {

// Fake adapter that records deliveries and can be told to fail (to exercise
// the dispatcher's retry path).
class FakeAdapter : public NotificationAdapter {
public:
  explicit FakeAdapter(const char *channel) : channel_(channel) {}

  bool deliver(const NotificationSubscriber &sub,
               const NotificationEvent &event) override {
    if (fail_first.load() > 0) {
      fail_first.fetch_sub(1);
      ++failed;
      return false;
    }
    ++delivered;
    last_event = event;
    last_subscriber = sub;
    return true;
  }

  const char *channel_name() const override { return channel_.c_str(); }

  std::string channel_;
  std::atomic<int> fail_first{0};
  std::atomic<int> delivered{0};
  std::atomic<int> failed{0};
  NotificationEvent last_event;
  NotificationSubscriber last_subscriber;
};

NotificationEvent make_event(NotificationEvent::EventType type,
                             NotificationEvent::Severity sev,
                             const std::string &summary = "test") {
  NotificationEvent e;
  e.type = type;
  e.severity = sev;
  e.timestamp = 1234567890;
  e.source = "test";
  e.actor = "test";
  e.summary = summary;
  return e;
}

class NotificationDispatcherTest : public ::testing::Test {
protected:
  void SetUp() override {
    conn_ = vhsm::signature_store::db::make_sqlite_connection(":memory:");
    ASSERT_TRUE(conn_ != nullptr);
    schema_ = std::make_unique<vhsm::signature_store::db::DbSchema>(*conn_);
    schema_->bootstrap();
    repo_ = std::make_unique<NotificationRepository>(*conn_);
    bus_ = std::make_unique<BoundedNotificationBus>(64);
    dispatcher_ = std::make_unique<NotificationDispatcher>(
        *bus_, *repo_,
        NotificationDispatcher::RetryPolicy(
            /*max_retries=*/2,
            /*base_delay_ms=*/1,
            /*max_delay_ms=*/5,
            /*multiplier=*/2));
    dispatcher_->start();
  }

  void TearDown() override {
    if (dispatcher_)
      dispatcher_->drain_and_stop();
  }

  // Wait until `adapter` has delivered at least `n` events (with timeout).
  bool wait_for_delivery(FakeAdapter &adapter, int n, int timeout_ms = 3000) {
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
      if (adapter.delivered.load() >= n)
        return true;
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return adapter.delivered.load() >= n;
  }

  std::unique_ptr<IDbConnection> conn_;
  std::unique_ptr<vhsm::signature_store::db::DbSchema> schema_;
  std::unique_ptr<NotificationRepository> repo_;
  std::unique_ptr<BoundedNotificationBus> bus_;
  std::unique_ptr<NotificationDispatcher> dispatcher_;
};

// ---------------------------------------------------------------------------
// Channel routing
// ---------------------------------------------------------------------------

TEST_F(NotificationDispatcherTest, RoutesEventToMatchingChannelAdapter) {
  ASSERT_TRUE(repo_->add_subscriber("sub1", "Alice", "email",
                                    "alice@example.com", "INFO", std::nullopt,
                                    true));

  FakeAdapter email("email");
  FakeAdapter webhook("webhook");
  dispatcher_->add_adapter(email);
  dispatcher_->add_adapter(webhook);

  bus_->publish(make_event(NotificationEvent::EventType::SIGN_CREATED,
                           NotificationEvent::Severity::INFO));

  ASSERT_TRUE(wait_for_delivery(email, 1));
  EXPECT_EQ(email.last_event.type, NotificationEvent::EventType::SIGN_CREATED);
  EXPECT_STREQ(email.last_subscriber.id.c_str(), "sub1");
  EXPECT_EQ(webhook.delivered.load(), 0);
}

TEST_F(NotificationDispatcherTest, EventWithNoMatchingAdapterIsSkippedNotHang) {
  ASSERT_TRUE(repo_->add_subscriber("sub1", "Alice", "email",
                                    "alice@example.com", "INFO", std::nullopt,
                                    true));

  // No adapter registered at all: the dispatcher must log SKIPPED and move on.
  bus_->publish(make_event(NotificationEvent::EventType::SIGN_CREATED,
                           NotificationEvent::Severity::INFO));

  // Give the loop a beat; nothing should have been delivered and it must not
  // crash or block.
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  EXPECT_EQ(dispatcher_->delivered_count(), 0u);
  EXPECT_EQ(dispatcher_->failed_count(), 0u);
}

// ---------------------------------------------------------------------------
// Severity gating
// ---------------------------------------------------------------------------

TEST_F(NotificationDispatcherTest, SeverityGateBlocksLowerSeverityEvents) {
  // Subscriber only accepts CRITICAL.
  ASSERT_TRUE(repo_->add_subscriber("sub1", "Alice", "email",
                                    "alice@example.com", "CRITICAL",
                                    std::nullopt, true));

  FakeAdapter email("email");
  dispatcher_->add_adapter(email);

  // INFO event is below the gate → not delivered.
  bus_->publish(make_event(NotificationEvent::EventType::SIGN_CREATED,
                           NotificationEvent::Severity::INFO));
  // CRITICAL event passes the gate.
  bus_->publish(make_event(NotificationEvent::EventType::DB_WRITE_FAILED,
                           NotificationEvent::Severity::CRITICAL));

  ASSERT_TRUE(wait_for_delivery(email, 1));
  EXPECT_EQ(email.last_event.type,
            NotificationEvent::EventType::DB_WRITE_FAILED);
}

TEST_F(NotificationDispatcherTest, SeverityGateAllowsEqualOrHigher) {
  ASSERT_TRUE(repo_->add_subscriber("sub1", "Alice", "email",
                                    "alice@example.com", "WARN", std::nullopt,
                                    true));

  FakeAdapter email("email");
  dispatcher_->add_adapter(email);

  bus_->publish(make_event(NotificationEvent::EventType::KEY_ROTATED,
                           NotificationEvent::Severity::WARNING));
  ASSERT_TRUE(wait_for_delivery(email, 1));
  EXPECT_EQ(email.last_event.type, NotificationEvent::EventType::KEY_ROTATED);
}

// ---------------------------------------------------------------------------
// Event-type filter
// ---------------------------------------------------------------------------

TEST_F(NotificationDispatcherTest, EventFilterThinsDeliveries) {
  // Subscriber only wants SIGN_CREATED events.
  ASSERT_TRUE(repo_->add_subscriber("sub1", "Alice", "email",
                                    "alice@example.com", "INFO",
                                    std::string("SIGN_CREATED"), true));

  FakeAdapter email("email");
  dispatcher_->add_adapter(email);

  bus_->publish(make_event(NotificationEvent::EventType::SIGN_CREATED,
                           NotificationEvent::Severity::INFO));
  bus_->publish(make_event(NotificationEvent::EventType::VERIFY_COMPLETED,
                           NotificationEvent::Severity::INFO));

  ASSERT_TRUE(wait_for_delivery(email, 1));
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  EXPECT_EQ(email.delivered.load(), 1);
  EXPECT_EQ(email.last_event.type, NotificationEvent::EventType::SIGN_CREATED);
}

// ---------------------------------------------------------------------------
// Retry / at-least-once for WARN & CRITICAL
// ---------------------------------------------------------------------------

TEST_F(NotificationDispatcherTest, WarnEventIsRetriedUntilDelivered) {
  ASSERT_TRUE(repo_->add_subscriber("sub1", "Alice", "email",
                                    "alice@example.com", "WARN", std::nullopt,
                                    true));

  FakeAdapter email("email");
  email.fail_first.store(1); // fail once, then succeed
  dispatcher_->add_adapter(email);

  bus_->publish(make_event(NotificationEvent::EventType::KEY_ROTATED,
                           NotificationEvent::Severity::WARNING));

  ASSERT_TRUE(wait_for_delivery(email, 1));
  EXPECT_GE(email.failed.load(), 1);
  EXPECT_GT(dispatcher_->delivered_count(), 0u);
}

TEST_F(NotificationDispatcherTest, InfoEventIsNotRetried) {
  ASSERT_TRUE(repo_->add_subscriber("sub1", "Alice", "email",
                                    "alice@example.com", "INFO", std::nullopt,
                                    true));

  FakeAdapter email("email");
  email.fail_first.store(10); // always fail
  dispatcher_->add_adapter(email);

  bus_->publish(make_event(NotificationEvent::EventType::SIGN_CREATED,
                           NotificationEvent::Severity::INFO));

  // INFO gets a single best-effort attempt (no retries).
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  EXPECT_EQ(email.delivered.load(), 0);
  EXPECT_EQ(email.failed.load(), 1);
  EXPECT_GT(dispatcher_->failed_count(), 0u);
}

TEST_F(NotificationDispatcherTest,
       EventPublishedBeforeSubscribersExistIsProcessedLater) {
  // Publish while there are no subscribers yet.
  bus_->publish(make_event(NotificationEvent::EventType::SIGN_CREATED,
                           NotificationEvent::Severity::INFO));
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  // Now add a subscriber + adapter; a later event should flow.
  ASSERT_TRUE(repo_->add_subscriber("sub1", "Alice", "email",
                                    "alice@example.com", "INFO", std::nullopt,
                                    true));
  FakeAdapter email("email");
  dispatcher_->add_adapter(email);

  bus_->publish(make_event(NotificationEvent::EventType::VERIFY_COMPLETED,
                           NotificationEvent::Severity::INFO));

  ASSERT_TRUE(wait_for_delivery(email, 1));
  EXPECT_EQ(email.last_event.type,
            NotificationEvent::EventType::VERIFY_COMPLETED);
}

} // namespace