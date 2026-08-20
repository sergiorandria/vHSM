#ifndef VHSM_ADMIN_HSM_ADMIN_GRPC_H
#define VHSM_ADMIN_HSM_ADMIN_GRPC_H

#include "hsm_admin.grpc.pb.h"

#include <string>

#include "../session/slot_manager.h"
#include "admin_service.h"

namespace vhsm::signature_store {
namespace db {
class IDbConnection;
} // namespace db
} // namespace vhsm::signature_store

namespace vhsm::keystore {
class Token;
} // namespace vhsm::keystore

namespace vhsm::ledger {
class LedgerClient;
class LedgerWorker;
} // namespace vhsm::ledger

namespace vhsm::admin {

// WHY a thin gRPC adapter over the transport-agnostic admin cores: the auth and
// backup/restore rules live in AdminLoginCore / TokenBackupCore (unit-tested
// directly); this class only (a) resolves the target token via the SlotManager
// singleton and (b) marshals gRPC request/response.  The signature/ledger/
// subscriber RPCs are likewise thin wrappers over the signature_store facades
// (SignatureQuery, LedgerRetryQueue, NotificationRepository).
//
// The db / token / ledger_client / ledger_worker members may be null for
// deployments that do not expose the corresponding features; the affected RPCs
// then return FAILED_PRECONDITION.
class HsmAdminServiceImpl final : public HsmAdmin::Service {
public:
  HsmAdminServiceImpl(vhsm::signature_store::db::IDbConnection *db,
                      vhsm::keystore::Token *token,
                      vhsm::ledger::LedgerClient *ledger_client,
                      vhsm::ledger::LedgerWorker *ledger_worker,
                      vhsm::notification::NotificationBus *bus,
                      vhsm::audit::AuditLog *audit_log);

  ::grpc::Status AdminLogin(::grpc::ServerContext *ctx,
                            const AdminLoginRequest *request,
                            AdminLoginResponse *response) override;

  ::grpc::Status BackupToken(::grpc::ServerContext *ctx,
                             const BackupTokenRequest *request,
                             BackupTokenResponse *response) override;

  ::grpc::Status RestoreToken(::grpc::ServerContext *ctx,
                              const RestoreTokenRequest *request,
                              RestoreTokenResponse *response) override;

  ::grpc::Status QuerySignatures(::grpc::ServerContext *ctx,
                                 const SignatureQuery *request,
                                 SignatureList *response) override;

  ::grpc::Status GetSignature(::grpc::ServerContext *ctx,
                              const GetSignatureRequest *request,
                              GetSignatureResponse *response) override;

  ::grpc::Status VerifySignature(::grpc::ServerContext *ctx,
                                 const VerifySignatureRequest *request,
                                 VerifySignatureResponse *response) override;

  ::grpc::Status ListPendingLedgerCommits(::grpc::ServerContext *ctx,
                                          const Empty *request,
                                          PendingLedgerList *response) override;

  ::grpc::Status RetryLedgerCommits(::grpc::ServerContext *ctx,
                                    const Empty *request,
                                    RetryLedgerResponse *response) override;

  ::grpc::Status AddSubscriber(::grpc::ServerContext *ctx,
                               const Subscriber *request,
                               SubscriberResponse *response) override;

  ::grpc::Status ListSubscribers(::grpc::ServerContext *ctx,
                                 const Empty *request,
                                 SubscriberList *response) override;

  ::grpc::Status RemoveSubscriber(::grpc::ServerContext *ctx,
                                  const SubscriberIdRequest *request,
                                  SubscriberResponse *response) override;

  ::grpc::Status QueryNotificationLog(::grpc::ServerContext *ctx,
                                      const NotificationLogQuery *request,
                                      NotificationLogList *response) override;

private:
  vhsm::signature_store::db::IDbConnection *const db_;
  vhsm::keystore::Token *const token_;
  vhsm::ledger::LedgerClient *const ledger_client_;
  vhsm::ledger::LedgerWorker *const ledger_worker_;
  vhsm::notification::NotificationBus *const bus_;
  vhsm::audit::AuditLog *const audit_log_;
};

} // namespace vhsm::admin

#endif // VHSM_ADMIN_HSM_ADMIN_GRPC_H