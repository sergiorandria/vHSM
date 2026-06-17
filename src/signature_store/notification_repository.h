#ifndef VHSM_SIGSTORE_NOTIFICATION_REPOSITORY_H
#define VHSM_SIGSTORE_NOTIFICATION_REPOSITORY_H

#include <string>
#include <vector>
#include <optional>
#include "db_connection.h"

namespace vhsm::signature_store {
namespace db {

class NotificationRepository {
public:
    explicit NotificationRepository(IDbConnection& conn);

    // Subscriber management
    bool add_subscriber(const std::string& id, const std::string& name,
                       const std::string& channel, const std::string& address,
                       const std::string& min_severity, const std::optional<std::string>& event_filter,
                       bool enabled);

    bool update_subscriber(const std::string& id, const std::string& name,
                          const std::string& channel, const std::string& address,
                          const std::string& min_severity, const std::optional<std::string>& event_filter,
                          bool enabled);

    bool remove_subscriber(const std::string& id);

    std::optional<std::vector<std::optional<std::string>>> get_subscriber(const std::string& id) const;
    std::vector<std::string> get_all_subscriber_ids() const;
    std::vector<std::string> get_enabled_subscriber_ids() const;

    // Notification log
    bool log_notification(const std::string& id, int64_t sent_at,
                         const std::string& event_id, const std::string& subscriber_id,
                         const std::string& outcome, int attempt_count,
                         const std::optional<std::string>& error_detail);

    std::vector<std::string> get_failed_notifications(int max_attempts) const;
    bool update_notification_outcome(const std::string& id, const std::string& outcome,
                                    int attempt_count, const std::optional<std::string>& error_detail);

private:
    IDbConnection& conn_;
};

}  // namespace db
}  // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_NOTIFICATION_REPOSITORY_H