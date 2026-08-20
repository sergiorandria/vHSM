#include "audit_log.h"

namespace vhsm::audit {

// Linkable stub implementation.  The real audit sink is wired in elsewhere;
// this no-op keeps the signature store linkable and allows tests to subclass
// and override `append`.
void AuditLog::append(const std::string &, const std::string &) {}

} // namespace vhsm::audit
