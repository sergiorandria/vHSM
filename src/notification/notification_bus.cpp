#include "notification_bus.h"

namespace vhsm::notification {

// Linkable stub implementation.  The real notification bus (email / webhook /
// background dispatcher) is wired in elsewhere; this no-op keeps the signature
// store linkable and allows tests to subclass and override `publish`.
void NotificationBus::publish(const NotificationEvent &) {}

} // namespace vhsm::notification
