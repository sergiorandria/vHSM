// WHY NotificationEvent is a struct (not a class): Notifications are data
// carriers, not logic containers. Struct signals immutability and transparency.
// The caller (SignatureDispatcher) populates all fields and sends it through
// the bus. Subscribers (audit, monitoring) consume it read-only. No methods
// needed; just fields.
//
// WHY EventType and Severity are separate enums: Type describes what happened
// (SIGN_CREATED, LEDGER_COMMITTED). Severity describes urgency (INFO = routine,
// CRITICAL = immediate action). Keeping them separate allows filtering (e.g.,
// "all CRITICAL events" or "all SIGN_* events").
//
// WHY timestamp is int64_t (epoch milliseconds): Matches HsmTimePoint precision
// (milliseconds). Epoch is portable (no timezone confusion). int64_t covers 292
// million years; sufficient for any practical system. Milliseconds are granular
// enough for auditing sequential operations.
//
// WHY include source, actor, summary, detail_json: Auditability trail. source
// identifies the component (SignatureDispatcher, LedgerWorker). actor is the
// user/system responsible. summary is human-readable (for logs). detail_json is
// machine-parseable (for analysis). Together, they enable both human operators
// and automated systems to understand events.
//
// WHY hsm_instance is optional (for multi-instance deployments): vHSM may run
// multiple instances (redundancy, load-balancing). Events include the instance
// ID so operators can correlate events across instances and identify
// single-instance failures.

#ifndef VHSM_NOTIFICATION_NOTIFICATION_EVENT_H
#define VHSM_NOTIFICATION_NOTIFICATION_EVENT_H

#include <cstdint>
#include <string>

namespace vhsm::notification {
struct NotificationEvent {
  // WHY enumerate event types: Explicit list prevents typos (compiler catches
  // misspellings). Event types signal system milestones: operations completed
  // (SIGN_CREATED, VERIFY_COMPLETED), successes (LEDGER_COMMITTED), failures
  // (DB_WRITE_FAILED, LEDGER_COMMIT_FAILED, VERIFY_FAILED), and security events
  // (KEY_ROTATED, KEY_DESTROYED, INTEGRITY_ALERT, ADMIN_LOGIN, PIN_LOCKOUT).
  // Each type signals a different class of action (subscribers may filter by
  // type).
  enum class EventType {
    SIGN_CREATED,         // Signature operation initiated
    DB_WRITE_FAILED,      // Persistence failure
    LEDGER_COMMIT_FAILED, // Blockchain commit failed (will retry)
    LEDGER_COMMITTED,     // Blockchain commit succeeded
    LEDGER_VERIFY_FAILED, // DB row vs. ledger cross-check failed
    VERIFY_COMPLETED,     // Signature verification succeeded
    VERIFY_FAILED,        // Signature verification failed
    ENCRYPT_COMPLETED,    // Encryption operation completed
    DECRYPT_COMPLETED,    // Decryption operation completed
    WRAP_KEY_COMPLETED,   // Key wrapping operation completed
    UNWRAP_KEY_COMPLETED, // Key unwrapping operation completed
    KEY_ROTATED,          // Key rotation event
    KEY_DESTROYED,        // Key destruction event
    INTEGRITY_ALERT,      // Integrity check failed (suspicious)
    ADMIN_LOGIN,          // Administrative user logged in
    PIN_LOCKOUT           // PIN locked after failed attempts
  };

  // WHY three severity levels (INFO, WARNING, CRITICAL): Operators prioritize
  // by urgency. INFO = routine operation (log it, but no action). WARNING =
  // problem detected but recoverable (check logs, may retry). CRITICAL =
  // immediate action required (alert on-call). Bridges automated monitoring
  // (thresholds) and human operators (escalation).
  enum class Severity {
    INFO,     // Routine event
    WARNING,  // Problem detected, recoverable
    CRITICAL, // Immediate action required
  };

  EventType type;
  Severity severity;
  int64_t timestamp;   // epoch milliseconds (for correlation + sequencing)
  std::string source;  // Component that generated the event
  std::string actor;   // User/system responsible (e.g., user label, "system")
  std::string summary; // Human-readable brief summary (for logs/dashboards)
  std::string detail_json;  // JSON with structured details (for machines + deep
                            // investigation)
  std::string hsm_instance; // HSM instance ID (for multi-instance correlation)
};
} // namespace vhsm::notification

#endif // VHSM_NOTIFICATION_NOTIFICATION_EVENT_H