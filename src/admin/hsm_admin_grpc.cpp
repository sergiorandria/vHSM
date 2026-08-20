#include "hsm_admin_grpc.h"

#include <memory>

#include "../keystore/slot.h"
#include "../keystore/token.h"

namespace vhsm::admin {

HsmAdminServiceImpl::HsmAdminServiceImpl(
    vhsm::notification::NotificationBus *bus, vhsm::audit::AuditLog *audit_log)
    : bus_(bus), audit_log_(audit_log) {}

namespace {

// Resolves slot -> token via the global SlotManager singleton (shared with the
// PKCS#11 module).  Returns nullptr (with a status string set) on failure.
std::shared_ptr<keystore::Token> resolve_token(uint32_t slot_id,
                                               std::string &err) {
  auto slot = vhsm::session::SlotManager::get_instance().get_slot(slot_id);
  if (!slot) {
    err = "slot not found: " + std::to_string(slot_id);
    return nullptr;
  }
  auto token = slot->get_token();
  if (!token) {
    err = "no token present in slot " + std::to_string(slot_id);
    return nullptr;
  }
  return token;
}

} // namespace

::grpc::Status HsmAdminServiceImpl::AdminLogin(::grpc::ServerContext * /*ctx*/,
                                               const AdminLoginRequest *request,
                                               AdminLoginResponse *response) {
  if (!request || !response) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "invalid request");
  }

  // Resolve the slot's token via the global SlotManager (the same registry
  // the PKCS#11 module uses).
  auto slot =
      vhsm::session::SlotManager::get_instance().get_slot(request->slot_id());
  if (!slot) {
    return ::grpc::Status(::grpc::StatusCode::NOT_FOUND,
                          "slot not found: " +
                              std::to_string(request->slot_id()));
  }
  auto token = slot->get_token();
  if (!token) {
    return ::grpc::Status(::grpc::StatusCode::NOT_FOUND,
                          "no token present in slot " +
                              std::to_string(request->slot_id()));
  }

  AdminLoginCore core(*token, bus_, audit_log_);
  const CK_RV rv =
      core.admin_login(request->role() == UserRole::SO ? CKU_SO : CKU_USER,
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
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "PIN_LOCKED");
  default:
    response->set_status("LOGIN_FAILED");
    return ::grpc::Status(::grpc::StatusCode::UNAUTHENTICATED, "LOGIN_FAILED");
  }
}

::grpc::Status
HsmAdminServiceImpl::BackupToken(::grpc::ServerContext * /*ctx*/,
                                 const BackupTokenRequest *request,
                                 BackupTokenResponse *response) {
  if (!request || !response || request->vault_path().empty() ||
      request->vault_password().empty()) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "vault_path and vault_password are required");
  }
  std::string err;
  auto token = resolve_token(request->slot_id(), err);
  if (!token) {
    return ::grpc::Status(::grpc::StatusCode::NOT_FOUND, err);
  }
  try {
    TokenBackupCore core(*token);
    core.backup(request->vault_path(), request->vault_password());
    response->set_status("OK");
    return ::grpc::Status::OK;
  } catch (const std::exception &e) {
    response->set_status(std::string("ERROR:") + e.what());
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION, e.what());
  }
}

::grpc::Status
HsmAdminServiceImpl::RestoreToken(::grpc::ServerContext * /*ctx*/,
                                  const RestoreTokenRequest *request,
                                  RestoreTokenResponse *response) {
  if (!request || !response || request->vault_path().empty() ||
      request->vault_password().empty()) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "vault_path and vault_password are required");
  }
  std::string err;
  auto token = resolve_token(request->slot_id(), err);
  if (!token) {
    return ::grpc::Status(::grpc::StatusCode::NOT_FOUND, err);
  }
  try {
    TokenBackupCore core(*token);
    core.restore(request->vault_path(), request->vault_password());
    response->set_status("OK");
    return ::grpc::Status::OK;
  } catch (const std::exception &e) {
    response->set_status(std::string("ERROR:") + e.what());
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION, e.what());
  }
}

} // namespace vhsm::admin