#ifndef VHSM_NOTIFICATION_NOTIFICATION_BUS_H
#define VHSM_NOTIFICATION_NOTIFICATION_BUS_H

#include "notification_event.h"

namespace vhsm::notification {
class NotificationBus {
public:
    // Publish a notification event to the bus.
    // The event is expected to be a struct with at least the following fields:
    // - type: an enum or string indicating the type of event (e.g., SIGN_CREATED, DB_WRITE_FAILED, etc.)
    // - severity: an enum or string indicating the severity of the event (e.g., INFO, WARNING, CRITICAL)
    // - timestamp: a timestamp indicating when the event occurred
    // - source: a string indicating the source of the event
    // - actor: a string indicating the actor responsible for the event (e.g., user label)
    // - summary: a brief summary of the event
    // - detail_json: a JSON string with additional details about the event
    // - hsm_instance: a string indicating the HSM instance involved (if applicable)
    void publish(const NotificationEvent& event);
};
} // namespace vhsm::notification
#endif // VHSM_NOTIFICATION_NOTIFICATION_BUS_H