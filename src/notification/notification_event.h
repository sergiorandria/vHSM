#ifndef VHSM_NOTIFICATION_NOTIFICATION_EVENT_H 
#define VHSM_NOTIFICATION_NOTIFICATION_EVENT_H

#include <string>

namespace vhsm::notification {
struct NotificationEvent {
    enum class EventType {
        SIGN_CREATED,
        DB_WRITE_FAILED,
        // Add more event types as needed
    };

    enum class Severity {
        INFO,
        WARNING,
        CRITICAL,
        // Add more severity levels as needed
    };

    EventType type;
    Severity severity;
    std::string timestamp; // ISO 8601 format
    std::string source;    // e.g., "SignatureStore"
    std::string actor;     // e.g., user label or system component
    std::string summary;   // Brief summary of the event
    std::string detail_json; // JSON string with additional details
    std::string hsm_instance; // HSM instance involved, if applicable
};
} // namespace vhsm::notification

#endif // VHSM_NOTIFICATION_NOTIFICATION_EVENT_H