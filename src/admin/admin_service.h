#ifndef VHSM_ADMIN_ADMIN_SERVICE_H
#define VHSM_ADMIN_ADMIN_SERVICE_H

#include <memory>
#include <string>

#include "../core/types.h"
#include "../keystore/token.h"
#include "../notification/notification_bus.h"
#include "../notification/notification_event.h"
#include "../audit/audit_log.h"

namespace vhsm::admin {

// WHY a pure C++ core (not gRPC-bound): the AdminLogin authentication logic and
// the ADMIN_LOGIN notification must be unit-testable without spinning up a gRPC
// server or a socket.  The gRPC service implementation (hsm_admin_grpc) is a
// thin adapter over this class and simply marshals request/response structs.
//
// The core authenticates a role's PIN against a token and, on success, publishes
// an ADMIN_LOGIN (INFO) event on the notification bus (spec: "SO or USER
// authenticated via gRPC admin").  Failed attempts fall through to the token's
// PIN lockout counter and return CKR_PIN_* codes unchanged.
class AdminLoginCore {
public:
    AdminLoginCore(keystore::Token& token,
                   vhsm::notification::NotificationBus* bus,
                   vhsm::audit::AuditLog* audit_log);

    // Attempt login.  Mirrors the CK_USER_TYPE semantics used by C_Login.
    // Returns CKR_OK on success; CKR_PIN_INCORRECT / CKR_PIN_LOCKED /
    // CKR_USER_TYPE_INVALID otherwise.  On success, publishes ADMIN_LOGIN.
    CK_RV admin_login(CK_USER_TYPE userType, const std::string& pin,
                      const std::string& caller);

    // The token this core authenticates against.
    keystore::Token& token() const noexcept { return token_; }

private:
    keystore::Token& token_;
    vhsm::notification::NotificationBus* const bus_;
    vhsm::audit::AuditLog* const audit_log_;
};

}  // namespace vhsm::admin

#endif  // VHSM_ADMIN_ADMIN_SERVICE_H