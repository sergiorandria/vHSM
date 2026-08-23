#ifndef VHSM_SIGSTORE_NOTIFICATION_REPOSITORY_H
#define VHSM_SIGSTORE_NOTIFICATION_REPOSITORY_H

#include "../notification/notification_subscriber.h"
#include "db_connection.h"
#include <optional>
#include <string>
#include <vector>

namespace vhsm::signature_store {
namespace db {

// A single row from the notification_log table, unpacked into plain fields so
// callers (e.g. the admin API) can inspect delivery outcomes without knowing
// the table layout.
struct NotificationLogRecord {
  std::string id;
  int64_t sent_at;
  std::string event_id;
  std::string subscriber_id;
  std::string outcome; // DELIVERED / RETRYING / FAILED / SKIPPED
  int attempt_count;
  std::string error_detail;
};

class NotificationRepository {
public:
  explicit NotificationRepository(IDbConnection &conn);

  // Subscriber management
  bool add_subscriber(const std::string &id, const std::string &name,
                      const std::string &channel, const std::string &address,
                      const std::string &min_severity,
                      const std::optional<std::string> &event_filter,
                      bool enabled);

  bool update_subscriber(const std::string &id, const std::string &name,
                         const std::string &channel, const std::string &address,
                         const std::string &min_severity,
                         const std::optional<std::string> &event_filter,
                         bool enabled);

  bool remove_subscriber(const std::string &id);

  std::optional<std::vector<std::optional<std::string>>>
  get_subscriber(const std::string &id) const;
  std::vector<std::string> get_all_subscriber_ids() const;
  std::vector<std::string> get_enabled_subscriber_ids() const;

  // Resolve every enabled subscriber as a typed struct (unpacks the DB row).
  // Used by the notification dispatcher to fan events out to channels.
  std::vector<vhsm::notification::NotificationSubscriber>
  get_enabled_subscribers() const;

  // Notification log
  bool log_notification(const std::string &id, int64_t sent_at,
                        const std::string &event_id,
                        const std::string &subscriber_id,
                        const std::string &outcome, int attempt_count,
                        const std::optional<std::string> &error_detail);

  std::vector<std::string> get_failed_notifications(int max_attempts) const;
  bool
  update_notification_outcome(const std::string &id, const std::string &outcome,
                              int attempt_count,
                              const std::optional<std::string> &error_detail);

  // Query the notification delivery log, newest first.  `subscriber_id`, if
  // non-empty, restricts to a single subscriber; `since` is an inclusive lower
  // bound on sent_at (unix seconds); `limit` caps the result (0 = unbounded).
  std::vector<NotificationLogRecord>
  query_log(const std::optional<std::string> &subscriber_id, int64_t since,
            int limit) const;

private:
  IDbConnection &conn_;
};

} // namespace db
} // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_NOTIFICATION_REPOSITORY_H