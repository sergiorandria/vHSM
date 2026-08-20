#ifndef VHSM_SIGSTORE_NOTIFICATION_DISPATCHER_H
#define VHSM_SIGSTORE_NOTIFICATION_DISPATCHER_H

// WHY NotificationDispatcher: the plan requires asynchronous delivery that
// never blocks a signing operation, with at-least-once delivery (bounded
// retries) for WARN/CRITICAL and best-effort for INFO.  This background thread
// consumes the bounded event bus, resolves the (DB-backed) subscriber list,
// routes each event to the right channel adapter, retries failures with
// exponential backoff, and records every delivery attempt in
// notification_log.

#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "../notification/bounded_notification_bus.h"
#include "../notification/notification_adapter.h"
#include "../notification/notification_subscriber.h"
#include "notification_repository.h"

namespace vhsm::signature_store {
namespace db {

using vhsm::notification::BoundedNotificationBus;
using vhsm::notification::NotificationAdapter;
using vhsm::notification::NotificationEvent;
using vhsm::notification::NotificationSubscriber;

class NotificationDispatcher {
public:
  // Retry policy for WARN/CRITICAL events.
  struct RetryPolicy {
    int max_retries;   // delivery attempts beyond the first
    int base_delay_ms; // backoff base (tests use ~1 ms)
    int max_delay_ms;
    int multiplier;
    RetryPolicy()
        : max_retries(3), base_delay_ms(500), max_delay_ms(30000),
          multiplier(2) {}
    RetryPolicy(int max_retries, int base_delay_ms, int max_delay_ms,
                int multiplier)
        : max_retries(max_retries), base_delay_ms(base_delay_ms),
          max_delay_ms(max_delay_ms), multiplier(multiplier) {}
  };

  NotificationDispatcher(BoundedNotificationBus &bus,
                         NotificationRepository &repo,
                         RetryPolicy retry = RetryPolicy());
  ~NotificationDispatcher();

  // Register the adapter used for a channel ("email", "webhook",
  // "grpc_push").  Ownership is NOT taken; the caller keeps adapters alive.
  void add_adapter(NotificationAdapter &adapter);

  // Start the consumer thread.
  void start();
  // Stop the consumer thread, delivering anything already dequeued best-effort.
  void drain_and_stop();

  // Diagnostics.
  std::size_t delivered_count() const { return delivered_.load(); }
  std::size_t failed_count() const { return failed_.load(); }

private:
  void dispatch_loop();

  // True if `event` should be delivered to `subscriber`.
  static bool matches(const NotificationSubscriber &sub,
                      const NotificationEvent &event);

  // Deliver with WARN/CRITICAL retry; returns true if delivered.  Logs each
  // attempt to notification_log.
  bool deliver_with_retry(const NotificationSubscriber &sub,
                          const NotificationEvent &event);

  // Canonical name for an event type (used by event_filter matching).
  static std::string event_type_name(const NotificationEvent &event);

  BoundedNotificationBus &bus_;
  NotificationRepository &repo_;
  RetryPolicy retry_;
  mutable std::mutex adapters_mutex_;
  std::unordered_map<std::string, NotificationAdapter *> adapters_;
  std::thread thread_;
  std::atomic<bool> running_{false};
  std::atomic<std::size_t> delivered_{0};
  std::atomic<std::size_t> failed_{0};
};

} // namespace db
} // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_NOTIFICATION_DISPATCHER_H