#ifndef VHSM_NOTIFICATION_NOTIFICATION_SUBSCRIBER_H
#define VHSM_NOTIFICATION_NOTIFICATION_SUBSCRIBER_H

#include <optional>
#include <string>

namespace vhsm::notification {

// A single row from the notification_subscribers table, unrolled into a plain
// struct so the dispatcher (and tests) do not depend on the DB layer.
struct NotificationSubscriber {
  std::string id;
  std::string name;
  std::string channel;                     // "email" | "webhook" | "grpc_push"
  std::string address;                     // e.g. email addr or URL
  std::string min_severity;                // "INFO" | "WARN" | "CRITICAL"
  std::optional<std::string> event_filter; // optional glob on event type
  bool enabled = true;
};

// Severity ordering used for filter checks: INFO < WARN < CRITICAL.
// Returns -1 if the string is not a recognized severity.
inline int severity_rank(const std::string &severity) {
  if (severity == "CRITICAL")
    return 3;
  if (severity == "WARN")
    return 2;
  if (severity == "INFO")
    return 1;
  return -1;
}

} // namespace vhsm::notification

#endif // VHSM_NOTIFICATION_NOTIFICATION_SUBSCRIBER_H