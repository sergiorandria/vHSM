#include "notification_repository.h"

#include "../core/error.h"

namespace vhsm::signature_store {
namespace db {

NotificationRepository::NotificationRepository(IDbConnection& conn) : conn_(conn) {}

bool NotificationRepository::add_subscriber(const std::string& id, const std::string& name,
                                           const std::string& channel, const std::string& address,
                                           const std::string& min_severity, const std::optional<std::string>& event_filter,
                                           bool enabled) {
    const std::string sql = R"SQL(
        INSERT INTO notification_subscribers (
            id, name, channel, address, min_severity, event_filter, enabled
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?
        );
    )SQL";

    try {
        conn_.exec(sql, {
            id, name, channel, address, min_severity,
            event_filter.value_or(""), std::to_string(enabled ? 1 : 0)
        });
        return true;
    } catch (const DbError& e) {
        return false;
    }
}

bool NotificationRepository::update_subscriber(const std::string& id, const std::string& name,
                                              const std::string& channel, const std::string& address,
                                              const std::string& min_severity, const std::optional<std::string>& event_filter,
                                              bool enabled) {
    const std::string sql = R"SQL(
        UPDATE notification_subscribers SET
            name = ?,
            channel = ?,
            address = ?,
            min_severity = ?,
            event_filter = ?,
            enabled = ?
        WHERE id = ?;
    )SQL";

    try {
        conn_.exec(sql, {
            name, channel, address, min_severity,
            event_filter.value_or(""), std::to_string(enabled ? 1 : 0), id
        });
        return true;
    } catch (const DbError& e) {
        return false;
    }
}

bool NotificationRepository::remove_subscriber(const std::string& id) {
    const std::string sql = R"SQL(
        DELETE FROM notification_subscribers WHERE id = ?;
    )SQL";

    try {
        conn_.exec(sql, {id});
        return true;
    } catch (const DbError& e) {
        return false;
    }
}

std::optional<std::vector<std::optional<std::string>>> NotificationRepository::get_subscriber(const std::string& id) const {
    const std::string sql = R"SQL(
        SELECT id, name, channel, address, min_severity, event_filter, enabled
        FROM notification_subscribers
        WHERE id = ?;
    )SQL";

    try {
        auto rs = conn_.query(sql, {id});
        if (rs.rows_.empty()) {
            return std::nullopt;
        }
        // We expect exactly one row.
        const DbRow& row = rs.rows_[0];
        std::vector<std::optional<std::string>> result;
        result.reserve(7);
        for (size_t i = 0; i < row.column_count(); ++i) {
            auto opt = row.get_string(i);
            if (i == 6) { // enabled column is integer
                if (opt) {
                    int val = std::stoi(*opt);
                    result.push_back(val != 0 ? std::make_optional<std::string>("true") : std::make_optional<std::string>("false"));
                } else {
                    result.push_back(std::nullopt);
                }
            } else {
                if (opt) {
                    if (opt->empty()) {
                        result.push_back(std::nullopt);
                    } else {
                        result.push_back(*opt);
                    }
                } else {
                    result.push_back(std::nullopt);
                }
            }
        }
        return result;
    } catch (const DbError& e) {
        return std::nullopt;
    }
}

std::vector<std::string> NotificationRepository::get_all_subscriber_ids() const {
    std::vector<std::string> ids;

    const std::string sql = R"SQL(
        SELECT id FROM notification_subscribers;
    )SQL";

    try {
        auto rs = conn_.query(sql);
        for (const auto& row : rs.rows_) {
            auto id_opt = row.get_string(0);
            if (id_opt) {
                ids.push_back(*id_opt);
            }
        }
    } catch (const DbError& e) {
        // Return empty vector on error
    }

    return ids;
}

std::vector<std::string> NotificationRepository::get_enabled_subscriber_ids() const {
    std::vector<std::string> ids;

    const std::string sql = R"SQL(
        SELECT id FROM notification_subscribers WHERE enabled = 1;
    )SQL";

    try {
        auto rs = conn_.query(sql);
        for (const auto& row : rs.rows_) {
            auto id_opt = row.get_string(0);
            if (id_opt) {
                ids.push_back(*id_opt);
            }
        }
    } catch (const DbError& e) {
        // Return empty vector on error
    }

    return ids;
}

bool NotificationRepository::log_notification(const std::string& id, int64_t sent_at,
                                             const std::string& event_id, const std::string& subscriber_id,
                                             const std::string& outcome, int attempt_count,
                                             const std::optional<std::string>& error_detail) {
    const std::string sql = R"SQL(
        INSERT INTO notification_log (
            id, sent_at, event_id, subscriber_id, outcome, attempt_count, error_detail
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?
        );
    )SQL";

    try {
        conn_.exec(sql, {
            id, std::to_string(sent_at), event_id, subscriber_id, outcome,
            std::to_string(attempt_count), error_detail.value_or("")
        });
        return true;
    } catch (const DbError& e) {
        return false;
    }
}

std::vector<std::string> NotificationRepository::get_failed_notifications(int max_attempts) const {
    std::vector<std::string> ids;

    const std::string sql = R"SQL(
        SELECT id FROM notification_log
        WHERE outcome = 'FAILED' AND attempt_count >= ?;
    )SQL";

    try {
        auto rs = conn_.query(sql, {std::to_string(max_attempts)});
        for (const auto& row : rs.rows_) {
            auto id_opt = row.get_string(0);
            if (id_opt) {
                ids.push_back(*id_opt);
            }
        }
    } catch (const DbError& e) {
        // Return empty vector on error
    }

    return ids;
}

bool NotificationRepository::update_notification_outcome(const std::string& id, const std::string& outcome,
                                                        int attempt_count, const std::optional<std::string>& error_detail) {
    const std::string sql = R"SQL(
        UPDATE notification_log SET
            outcome = ?,
            attempt_count = ?,
            error_detail = ?
        WHERE id = ?;
    )SQL";

    try {
        conn_.exec(sql, {
            outcome, std::to_string(attempt_count), error_detail.value_or(""), id
        });
        return true;
    } catch (const DbError& e) {
        return false;
    }
}

}  // namespace db
}  // namespace vhsm::signature_store