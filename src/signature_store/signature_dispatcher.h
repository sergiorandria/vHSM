#ifndef VHSM_SIGSTORE_SIGNATURE_DISPATCHER_H
#define VHSM_SIGSTORE_SIGNATURE_DISPATCHER_H

#include <string>
#include <optional>
#include <vector>

#include "../core/types.h"
#include "db_connection.h"
#include "signature_repository.h"

// Forward declarations for dependencies (assume they exist in other modules)
namespace vhsm::notification {
class NotificationBus;
enum class EventType;
enum class Severity;
struct NotificationEvent;
} // namespace vhsm::notification

namespace vhsm::audit {
class AuditLog;
} // namespace vhsm::audit

namespace vhsm::rekor {
class RekorClient;
struct RekorEntry;
struct HashedRekordPayload;
} // namespace vhsm::rekor

namespace vhsm::signature_store {
namespace db {

class SignatureDispatcher {
public:
    SignatureDispatcher(
        IDbConnection& conn,
        vhsm::notification::NotificationBus& notification_bus,
        vhsm::audit::AuditLog& audit_log,
        vhsm::rekor::RekorClient& rekor_client);

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
    SignatureRepository signature_repository_;
    vhsm::notification::NotificationBus& notification_bus_;
    vhsm::audit::AuditLog& audit_log_;
    vhsm::rekor::RekorClient& rekor_client_;

    // Builds a Rekor payload from the sign result and context.
    vhsm::rekor::HashedRekordPayload build_rekor_payload(
        const vhsm::crypto::SignResult& sign_result,
        const std::string& key_id,
        const std::string& key_fingerprint) const;
};

}  // namespace db
}  // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_SIGNATURE_DISPATCHER_H