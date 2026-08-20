#include "bounded_notification_bus.h"

#include <chrono>

namespace vhsm::notification {

BoundedNotificationBus::BoundedNotificationBus(std::size_t capacity)
    : capacity_(capacity > 0 ? capacity : 1) {}

void BoundedNotificationBus::publish(const NotificationEvent& event) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() >= capacity_) {
            ++dropped_;  // full → drop the newest event
            return;
        }
        queue_.push_back(event);
    }
    cv_.notify_one();
}

bool BoundedNotificationBus::try_pop(NotificationEvent& out) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (queue_.empty()) {
        return false;
    }
    out = std::move(queue_.front());
    queue_.pop_front();
    return true;
}

bool BoundedNotificationBus::pop_timeout(NotificationEvent& out, int timeout_ms) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (!cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                      [this] { return !queue_.empty(); })) {
        return false;
    }
    out = std::move(queue_.front());
    queue_.pop_front();
    return true;
}

std::size_t BoundedNotificationBus::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

std::size_t BoundedNotificationBus::dropped_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return dropped_;
}

}  // namespace vhsm::notification