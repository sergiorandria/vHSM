// bounded_bus_test.cpp — Unit tests for BoundedNotificationBus: bounded
// capacity, non-blocking publish, drop-on-full accounting and blocking
// pop_timeout semantics.  This is the transport the NotificationDispatcher
// drains; overflow behaviour here is what keeps C_Sign producers unblocked
// under high load.

#include <gtest/gtest.h>

#include <chrono>
#include <thread>

#include "bounded_notification_bus.h"
#include "notification_event.h"

using vhsm::notification::BoundedNotificationBus;
using vhsm::notification::NotificationEvent;

namespace {

NotificationEvent make_event(const char *summary = "test") {
  NotificationEvent e;
  e.type = NotificationEvent::EventType::SIGN_CREATED;
  e.severity = NotificationEvent::Severity::INFO;
  e.timestamp = 1234567890;
  e.source = "test";
  e.actor = "test";
  e.summary = summary;
  return e;
}

TEST(BoundedNotificationBusTest, EmptyBusTryPopReturnsFalse) {
  BoundedNotificationBus bus(4);
  NotificationEvent out;
  EXPECT_FALSE(bus.try_pop(out));
  EXPECT_EQ(bus.size(), 0u);
  EXPECT_EQ(bus.dropped_count(), 0u);
}

TEST(BoundedNotificationBusTest, PublishesAndPopsFifoOrder) {
  BoundedNotificationBus bus(8);
  bus.publish(make_event("first"));
  bus.publish(make_event("second"));
  EXPECT_EQ(bus.size(), 2u);

  NotificationEvent out;
  EXPECT_TRUE(bus.try_pop(out));
  EXPECT_STREQ(out.summary.c_str(), "first");
  EXPECT_TRUE(bus.try_pop(out));
  EXPECT_STREQ(out.summary.c_str(), "second");
  EXPECT_FALSE(bus.try_pop(out));
}

TEST(BoundedNotificationBusTest, OverflowDropsNewestAndCounts) {
  BoundedNotificationBus bus(2);
  bus.publish(make_event("a"));
  bus.publish(make_event("b"));
  // Queue full: newest event is dropped, counter incremented, publish returns
  // immediately (never blocks).
  bus.publish(make_event("c"));
  EXPECT_EQ(bus.size(), 2u);
  EXPECT_EQ(bus.dropped_count(), 1u);

  NotificationEvent out;
  EXPECT_TRUE(bus.try_pop(out));
  EXPECT_STREQ(out.summary.c_str(), "a");
  EXPECT_TRUE(bus.try_pop(out));
  EXPECT_STREQ(out.summary.c_str(), "b");
  EXPECT_FALSE(bus.try_pop(out));
  EXPECT_EQ(bus.dropped_count(), 1u);
}

TEST(BoundedNotificationBusTest, PopTimeoutReturnsOnEvent) {
  BoundedNotificationBus bus(4);
  std::thread producer([&bus] {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    bus.publish(make_event("wake"));
  });

  NotificationEvent out;
  const bool got = bus.pop_timeout(out, 2000);
  producer.join();

  EXPECT_TRUE(got);
  EXPECT_STREQ(out.summary.c_str(), "wake");
}

TEST(BoundedNotificationBusTest, PopTimeoutExpiresWithNoEvent) {
  BoundedNotificationBus bus(4);
  NotificationEvent out;
  const auto start = std::chrono::steady_clock::now();
  const bool got = bus.pop_timeout(out, 100);
  const auto elapsed = std::chrono::steady_clock::now() - start;
  EXPECT_FALSE(got);
  // Must have waited approximately the timeout (upper bound generous to avoid
  // flakes; lower bound shows it actually blocked).
  EXPECT_GE(
      std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(),
      80);
}

TEST(BoundedNotificationBusTest, ZeroCapacityForcesMinimumOfOne) {
  BoundedNotificationBus bus(0);
  bus.publish(make_event("only"));
  NotificationEvent out;
  EXPECT_TRUE(bus.try_pop(out));
  EXPECT_FALSE(bus.try_pop(out));
}

} // namespace