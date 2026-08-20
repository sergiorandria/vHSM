#ifndef VHSM_NOTIFICATION_BOUNDED_NOTIFICATION_BUS_H
#define VHSM_NOTIFICATION_BOUNDED_NOTIFICATION_BUS_H

// WHY BoundedNotificationBus: producers (SignatureDispatcher, LedgerWorker,
// keystore) must never block on a slow consumer, and memory must be bounded.
// This is the "bounded in-memory queue (capacity 1024)" from the plan.
// publish() is non-blocking: if the ring is full it drops the NEWEST event and
// increments the dropped counter.  A single consumer (NotificationDispatcher)
// drains events with try_pop().  WARN/CRITICAL delivery guarantees are handled
// by the dispatcher (at-least-once with retries), not by the bus itself.
//
// WHY not a lock-free SPSC queue: producer and consumer live on different
// threads but there are MANY producers (any PKCS#11 op thread).  A mutex +
// condition variable is simpler and correct for N→1; the plan's "lock-free
// ring buffer" is a performance aspiration we honor with a bounded ring plus a
// short critical section.

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>

#include "notification_bus.h"

namespace vhsm::notification {

class BoundedNotificationBus : public NotificationBus {
public:
    // capacity: maximum number of undelivered events buffered.
    explicit BoundedNotificationBus(std::size_t capacity = 1024);

    // Enqueue `event` for delivery.  Never blocks.  If the queue is full the
    // event is dropped and dropped_count() is incremented.
    void publish(const NotificationEvent& event) override;

    // Pop one pending event.  Returns true and fills `out` if an event was
    // dequeued, false if the queue is empty.
    bool try_pop(NotificationEvent& out);

    // Blocking variant: waits up to `timeout_ms` for an event.  Returns true
    // if an event was dequeued.  Used by the dispatcher loop between sweeps.
    bool pop_timeout(NotificationEvent& out, int timeout_ms);

    // Number of events currently buffered (diagnostics / tests).
    std::size_t size() const;

    // Number of events dropped because the queue was full (diagnostics).
    std::size_t dropped_count() const;

private:
    const std::size_t capacity_;
    std::deque<NotificationEvent> queue_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::size_t dropped_{0};
};

}  // namespace vhsm::notification

#endif // VHSM_NOTIFICATION_BOUNDED_NOTIFICATION_BUS_H