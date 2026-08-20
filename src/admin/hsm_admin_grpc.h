#ifndef VHSM_ADMIN_HSM_ADMIN_GRPC_H
#define VHSM_ADMIN_HSM_ADMIN_GRPC_H

#include "hsm_admin.grpc.pb.h"

#include <string>

#include "admin_service.h"
#include "../session/slot_manager.h"

namespace vhsm::admin {

// WHY a thin gRPC adapter over AdminLoginCore: the core is transport-agnostic
// and unit-tested directly; this class only (a) resolves the target token via
// the SlotManager singleton and (b) marshals the gRPC request/response.
// Keeping the adapter free of business logic means the authentication rules
// live in exactly one testable place.
class HsmAdminServiceImpl final : public HsmAdmin::Service {
public:
    HsmAdminServiceImpl(vhsm::notification::NotificationBus* bus,
                        vhsm::audit::AuditLog* audit_log);

    ::grpc::Status AdminLogin(::grpc::ServerContext* ctx,
                              const AdminLoginRequest* request,
                              AdminLoginResponse* response) override;

private:
    vhsm::notification::NotificationBus* const bus_;
    vhsm::audit::AuditLog* const audit_log_;
};

}  // namespace vhsm::admin

#endif  // VHSM_ADMIN_HSM_ADMIN_GRPC_H