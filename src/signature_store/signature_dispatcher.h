#ifndef VHSM_SIGSTORE_SIGNATURE_DISPATCHER_H
#define VHSM_SIGSTORE_SIGNATURE_DISPATCHER_H

#include <string>
#include <optional>
#include <vector>

#include "../core/types.h"
#include "db_connection.h"
#include "signature_repository.h"
#include "../keystore/token.h"
#include "../notification/notification_bus.h"
#include "../notification/notification_event.h"
#include "../audit/audit_log.h"

namespace vhsm::signature_store {
namespace db {

class SignatureDispatcher {
public:
    SignatureDispatcher(
        IDbConnection& conn,
        vhsm::keystore::Token& token,
        vhsm::notification::NotificationBus& notification_bus,
        vhsm::audit::AuditLog& audit_log);

    // Dispatch a signature operation result.
    // This method builds a SignatureRecord from the SignResult and context,
    // persists it to the DB, logs it to the audit log, publishes a notification,
    // and asynchronously submits it to Rekor.
    void dispatch(
        const vhsm::crypto::SignResult& sign_result,
        int64_t created_at,
        int slot_id,
        const std::string& token_label,
        const std::string& key_id,
        const std::string& key_fingerprint,
        const std::string& mechanism,
        const std::string& digest_algorithm,
        const std::string& session_handle,
        const std::optional<std::string>& user_label,
        const std::optional<std::string>& app_context);

private:
    IDbConnection& conn_;
    vhsm::keystore::Token& token_;
    SignatureRepository signature_repository_;
    vhsm::notification::NotificationBus& notification_bus_;
    vhsm::audit::AuditLog& audit_log_;
};

}  // namespace db
}  // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_SIGNATURE_DISPATCHER_H