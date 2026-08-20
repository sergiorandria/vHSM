#ifndef VHSM_NOTIFICATION_NOTIFICATION_ADAPTER_H
#define VHSM_NOTIFICATION_NOTIFICATION_ADAPTER_H

// WHY adapter interface: each delivery channel (email, webhook, gRPC push)
// has a different transport but the dispatcher treats them uniformly.  The
// interface hides the transport; concrete adapters may substitute a real
// transport or a test double (mock transport function injected in the ctor).
//
// Channels used to route events (mirrors the SQL CHECK on
// notification_subscribers.channel): "email", "webhook", "grpc_push".

#include <functional>
#include <string>

#include "notification_event.h"
#include "notification_subscriber.h"

namespace vhsm::notification {

class NotificationAdapter {
public:
    virtual ~NotificationAdapter() = default;

    // Deliver `event` to `subscriber`.  Returns true on success.  The
    // dispatcher retries WARN/CRITICAL events when this returns false.
    virtual bool deliver(const NotificationSubscriber& subscriber,
                         const NotificationEvent& event) = 0;

    // Human-readable channel name ("email", "webhook", "grpc_push").
    virtual const char* channel_name() const = 0;
};

}  // namespace vhsm::notification

#endif // VHSM_NOTIFICATION_NOTIFICATION_ADAPTER_H