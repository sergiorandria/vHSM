#ifndef VHSM_CORE_TYPES_H
#define VHSM_CORE_TYPES_H

#include <cstdint>
#include <string>
#include <vector>

typedef std::uint8_t u8;
typedef std::uint16_t u16;
typedef std::uint32_t u32;

namespace vhsm::crypto {
// SignResult struct returned by CryptoEngine::sign()
struct SignResult {
    std::vector<u8> signature;      // raw DER bytes
    std::string          mechanism_str;  // e.g., "CKM_ECDSA_SHA256"
    std::string          digest_alg;     // e.g., "SHA-256"
    std::string          payload_digest; // hex SHA-256 of input
    size_t               payload_size;
};

// Enumerations for NotificationEvent
enum class EventType {
    SIGN_CREATED,
    VERIFY_COMPLETED,
    VERIFY_FAILED,
    KEY_ROTATED,
    KEY_DESTROYED,
    INTEGRITY_ALERT,
    DB_WRITE_FAILED,
    ADMIN_LOGIN,
    PIN_LOCKOUT
};

enum class Severity {
    INFO,
    WARN,
    CRITICAL
};

// NotificationEvent struct used by the notification bus
struct NotificationEvent {
    std::string  event_id;       // UUID v4
    EventType    type;           // SIGN_CREATED, VERIFY_FAILED, etc.
    Severity     severity;       // INFO | WARN | CRITICAL
    int64_t      timestamp;      // epoch ms
    std::string  source;         // "slot:N/token:label"
    std::string  actor;          // user_label or "SO"
    std::string  summary;        // short human-readable
    std::string  detail_json;    // JSON payload
    std::string  hsm_instance;   // instance_id from db_meta
};
} // namespace vhsm::crypto
#endif // VHSM_CORE_TYPES_H