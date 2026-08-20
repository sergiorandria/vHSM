#include "notification_dispatcher.h"

#include <chrono>
#include <exception>
#include <thread>

#include "../core/utils.h"

namespace vhsm::signature_store {
namespace db {

NotificationDispatcher::NotificationDispatcher(BoundedNotificationBus& bus,
                                               NotificationRepository& repo,
                                               RetryPolicy retry)
    : bus_(bus), repo_(repo), retry_(retry) {}

NotificationDispatcher::~NotificationDispatcher() {
    if (thread_.joinable()) {
        drain_and_stop();
    }
}

void NotificationDispatcher::add_adapter(NotificationAdapter& adapter) {
    std::lock_guard<std::mutex> lock(adapters_mutex_);
    adapters_[adapter.channel_name()] = &adapter;
}

void NotificationDispatcher::start() {
    if (running_) return;
    running_ = true;
    thread_ = std::thread(&NotificationDispatcher::dispatch_loop, this);
}

void NotificationDispatcher::drain_and_stop() {
    if (!running_) return;
    running_ = false;
    if (thread_.joinable()) {
        thread_.join();
    }
    // Best-effort final sweep of whatever is still buffered (events that were
    // published while the thread stopped).  WARN/CRITICAL still get retries;
    // nothing blocks producers.
    NotificationEvent event;
    while (bus_.try_pop(event)) {
        try {
            for (const auto& sub : repo_.get_enabled_subscribers()) {
                if (matches(sub, event)) {
                    deliver_with_retry(sub, event);
                }
            }
        } catch (const std::exception&) {
            // Best-effort delivery must never throw out of Finalize.
        }
    }
}

std::string NotificationDispatcher::event_type_name(const NotificationEvent& event) {
    switch (event.type) {
        case NotificationEvent::EventType::SIGN_CREATED:        return "SIGN_CREATED";
        case NotificationEvent::EventType::DB_WRITE_FAILED:     return "DB_WRITE_FAILED";
        case NotificationEvent::EventType::LEDGER_COMMIT_FAILED:return "LEDGER_COMMIT_FAILED";
        case NotificationEvent::EventType::LEDGER_COMMITTED:    return "LEDGER_COMMITTED";
        case NotificationEvent::EventType::LEDGER_VERIFY_FAILED:return "LEDGER_VERIFY_FAILED";
        case NotificationEvent::EventType::VERIFY_COMPLETED:    return "VERIFY_COMPLETED";
        case NotificationEvent::EventType::VERIFY_FAILED:       return "VERIFY_FAILED";
        case NotificationEvent::EventType::ENCRYPT_COMPLETED:   return "ENCRYPT_COMPLETED";
        case NotificationEvent::EventType::DECRYPT_COMPLETED:   return "DECRYPT_COMPLETED";
        case NotificationEvent::EventType::WRAP_KEY_COMPLETED:  return "WRAP_KEY_COMPLETED";
        case NotificationEvent::EventType::UNWRAP_KEY_COMPLETED:return "UNWRAP_KEY_COMPLETED";
        case NotificationEvent::EventType::KEY_ROTATED:         return "KEY_ROTATED";
        case NotificationEvent::EventType::KEY_DESTROYED:       return "KEY_DESTROYED";
        case NotificationEvent::EventType::INTEGRITY_ALERT:     return "INTEGRITY_ALERT";
        case NotificationEvent::EventType::ADMIN_LOGIN:         return "ADMIN_LOGIN";
        case NotificationEvent::EventType::PIN_LOCKOUT:         return "PIN_LOCKOUT";
    }
    return "UNKNOWN";
}

bool NotificationDispatcher::matches(const NotificationSubscriber& sub,
                                     const NotificationEvent& event) {
    if (!sub.enabled) {
        return false;
    }
    // Severity gate: subscriber must be willing to accept this severity or
    // higher (rank ordering CRITICAL > WARN > INFO).
    const int sub_rank = vhsm::notification::severity_rank(sub.min_severity);
    int event_rank = 1;
    switch (event.severity) {
        case NotificationEvent::Severity::CRITICAL: event_rank = 3; break;
        case NotificationEvent::Severity::WARNING:  event_rank = 2; break;
        case NotificationEvent::Severity::INFO:     event_rank = 1; break;
    }
    if (sub_rank > 0 && event_rank < sub_rank) {
        return false;
    }

    // Event filter gate: optional comma-separated substring list on the event
    // type name.  Empty filter matches everything.
    if (sub.event_filter && !sub.event_filter->empty()) {
        const std::string name = event_type_name(event);
        const std::string filter = *sub.event_filter;
        std::size_t start = 0;
        bool matched = false;
        while (start <= filter.size()) {
            std::size_t comma = filter.find(',', start);
            std::string token = filter.substr(start, comma - start);
            // trim
            auto first = token.find_first_not_of(" \t");
            auto last  = token.find_last_not_of(" \t");
            if (first != std::string::npos) {
                token = token.substr(first, last - first + 1);
            }
            if (!token.empty() && name.find(token) != std::string::npos) {
                matched = true;
                break;
            }
            if (comma == std::string::npos) break;
            start = comma + 1;
        }
        if (!matched) {
            return false;
        }
    }
    return true;
}

bool NotificationDispatcher::deliver_with_retry(const NotificationSubscriber& sub,
                                                const NotificationEvent& event) {
    NotificationAdapter* adapter_ptr = nullptr;
    {
        std::lock_guard<std::mutex> lock(adapters_mutex_);
        auto it = adapters_.find(sub.channel);
        if (it == adapters_.end()) {
            // No adapter registered for this channel → log SKIPPED.
            repo_.log_notification(vhsm::utils::uuid_v4(), event.timestamp,
                                   event_type_name(event), sub.id, "SKIPPED", 1,
                                   "no adapter for channel: " + sub.channel);
            return false;
        }
        adapter_ptr = it->second;
    }
    NotificationAdapter& adapter = *adapter_ptr;

    bool warn_or_critical = (event.severity != NotificationEvent::Severity::INFO);
    const int retries = warn_or_critical ? retry_.max_retries : 0;

    std::string last_error;
    bool ok = false;
    for (int attempt = 0; attempt <= retries; ++attempt) {
        ok = adapter.deliver(sub, event);
        if (ok) {
            break;
        }
        last_error = "attempt " + std::to_string(attempt + 1) + " failed";
        // Backoff before the next attempt (skip after the final one).
        if (attempt < retries) {
            int delay = retry_.base_delay_ms;
            for (int i = 0; i < attempt; ++i) {
                delay *= retry_.multiplier;
                if (delay > retry_.max_delay_ms) {
                    delay = retry_.max_delay_ms;
                    break;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
        }
        repo_.log_notification(vhsm::utils::uuid_v4(), event.timestamp,
                               event_type_name(event), sub.id,
                               attempt < retries ? "RETRYING" : "FAILED",
                               attempt + 1, last_error);
    }

    if (ok) {
        ++delivered_;
        repo_.log_notification(vhsm::utils::uuid_v4(), event.timestamp,
                               event_type_name(event), sub.id, "DELIVERED",
                               1, "");
        return true;
    }

    ++failed_;
    // Failure already logged above (FAILED).
    return false;
}

void NotificationDispatcher::dispatch_loop() {
    // Refresh the subscriber list per event so admin changes to the registry
    // take effect without a restart.  The list is small; re-querying is cheap.
    while (running_) {
        NotificationEvent event;
        try {
            if (!bus_.pop_timeout(event, 200)) {
                continue;
            }
        } catch (const std::exception&) {
            // Bus issues must never kill the process; keep draining.
            continue;
        }

        try {
            const auto subscribers = repo_.get_enabled_subscribers();
            if (subscribers.empty()) {
                // No one to notify — treated as successful (nothing failed).
                continue;
            }
            for (const auto& sub : subscribers) {
                if (matches(sub, event)) {
                    deliver_with_retry(sub, event);
                }
            }
        } catch (const std::exception&) {
            // A failing subscriber query/adapter must not terminate the process.
            ++failed_;
        }
    }
}

}  // namespace db
}  // namespace vhsm::signature_store