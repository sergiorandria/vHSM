#include "hsm_admin_grpc.h"

#include <memory>

#include "../keystore/slot.h"
#include "../keystore/token.h"

namespace vhsm::admin {

HsmAdminServiceImpl::HsmAdminServiceImpl(vhsm::notification::NotificationBus* bus,
                                         vhsm::audit::AuditLog* audit_log)
    : bus_(bus), audit_log_(audit_log) {}

::grpc::Status HsmAdminServiceImpl::AdminLogin(::grpc::ServerContext* /*ctx*/,
                                               const AdminLoginRequest* request,
                                               AdminLoginResponse* response) {
    if (!request || !response) {
        return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                              "invalid request");
    }

    // Resolve the slot's token via the global SlotManager (the same registry
    // the PKCS#11 module uses).
    auto slot = vhsm::session::SlotManager::get_instance().get_slot(request->slot_id());
    if (!slot) {
        return ::grpc::Status(::grpc::StatusCode::NOT_FOUND,
                              "slot not found: " + std::to_string(request->slot_id()));
    }
    auto token = slot->get_token();
    if (!token) {
        return ::grpc::Status(::grpc::StatusCode::NOT_FOUND,
                              "no token present in slot " + std::to_string(request->slot_id()));
    }

    AdminLoginCore core(*token, bus_, audit_log_);
    const CK_RV rv = core.admin_login(
        request->role() == UserRole::SO ? CKU_SO : CKU_USER,
        request->pin(), request->caller());

    // Map the PKCS#11 result to a gRPC status + a human-readable status string.
    // FAILED_PRECONDITION carries credential errors; callers should not treat
    // a wrong PIN as a server-side failure.
    // (We do not return the session token in this slice; that is added with the
    //  session/RPC-auth slice.)
    switch (rv) {
        case CKR_OK:
            response->set_status("OK");
            return ::grpc::Status::OK;
        case CKR_PIN_INCORRECT:
            response->set_status("PIN_INCORRECT");
            return ::grpc::Status(::grpc::StatusCode::UNAUTHENTICATED, "PIN_INCORRECT");
        case CKR_PIN_LOCKED:
            response->set_status("PIN_LOCKED");
            return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION, "PIN_LOCKED");
        default:
            response->set_status("LOGIN_FAILED");
            return ::grpc::Status(::grpc::StatusCode::UNAUTHENTICATED, "LOGIN_FAILED");
    }
}

}  // namespace vhsm::admin