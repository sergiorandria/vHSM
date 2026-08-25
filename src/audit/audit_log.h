#ifndef VHSM_AUDIT_LOG_H
#define VHSM_AUDIT_LOG_H

#include <string>

namespace vhsm::audit {
class AuditLog {
public:
  // WHY virtual dtor: derived P11AuditLog is held via unique_ptr<AuditLog>
  // (g_auditLog); deleting through the base without a virtual dtor is UB.
  virtual ~AuditLog() = default;

  // Log an audit event with the given details.
  // The details can include fields like: event type, timestamp, source, actor,
  // summary, and any relevant metadata.
  virtual void append(const std::string &event_id,
                      const std::string &event_type);
};
} // namespace vhsm::audit

#endif // VHSM_AUDIT_LOG_H