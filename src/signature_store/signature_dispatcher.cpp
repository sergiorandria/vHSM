#include "signature_dispatcher.h"

namespace vhsm::signature_store {
namespace db {

SignatureDispatcher::SignatureDispatcher(
    IDbConnection& conn,
    vhsm::keystore::Token& token,
    vhsm::notification::NotificationBus& notification_bus,
    vhsm::audit::AuditLog& audit_log,
    vhsm::ledger::LedgerWorker* ledger_worker)
   : v_clock_(),
     v_core_(conn, token, notification_bus, audit_log, ledger_worker, v_clock_) {
}

void SignatureDispatcher::dispatch(
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
    const std::optional<std::string>& app_context) {
    // Public API: validate user-supplied input before delegating to the
    // internal core.  Degenerate signatures are rejected fail-closed so we
    // never persist or anchor meaningless records.
    if (sign_result.signature.empty() ||
        key_fingerprint.empty() ||
        mechanism.empty()) {
        return;
    }

    vhsm::signature_store::db::internal::v_SignatureDispatchInput_M1 input;
    input.sign_result       = sign_result;
    input.created_at        = created_at;
    input.slot_id           = slot_id;
    input.token_label       = token_label;
    input.key_id            = key_id;
    input.key_fingerprint   = key_fingerprint;
    input.mechanism         = mechanism;
    input.digest_algorithm  = digest_algorithm;
    input.session_handle    = session_handle;
    input.user_label        = user_label;
    input.app_context       = app_context;

    v_core_.v_dispatch(input);
}

}  // namespace db
}  // namespace vhsm::signature_store
