#include "signature_dispatcher.h"

#include "../core/utils.h"

#include <chrono>
#include <sstream>
#include <vector>

// Include the dependencies (now fully defined)
#include "../notification/notification_bus.h"
#include "../notification/notification_event.h"
#include "../audit/audit_log.h"

namespace vhsm::signature_store {
namespace db {

SignatureDispatcher::SignatureDispatcher(
    IDbConnection& conn,
    vhsm::keystore::Token& token,
    vhsm::notification::NotificationBus& notification_bus,
    vhsm::audit::AuditLog& audit_log)
   
    : conn_(conn),
      token_(token),
      signature_repository_(conn, token),
      notification_bus_(notification_bus),
      audit_log_(audit_log)
      // rekor_client_(rekor_client) // Removed for Phase 4
{
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
    // Build the SignatureRecord fields.
    std::string payload_digest = sign_result.payload_digest; // already hex string
    std::string signature_b64 = vhsm::utils::base64_encode(
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(sign_result.signature.data()),
            sign_result.signature.size()));

    // Insert into DB
    auto signature_id_opt = signature_repository_.insert(
        created_at,
        slot_id,
        token_label,
        key_id,
        key_fingerprint,
        mechanism,
        digest_algorithm,
        payload_digest,
        static_cast<int>(sign_result.signature.size()), // payload_size
        signature_b64,
        session_handle,
        user_label,
        app_context);

    if (!signature_id_opt) {
        // If we cannot persist to DB, we should notify and maybe throw?
        // For now, we'll just return (or we could publish a DB_WRITE_FAILED event).
        // We'll publish a DB_WRITE_FAILED notification.
        vhsm::notification::NotificationEvent event;
        event.type = vhsm::notification::NotificationEvent::EventType::DB_WRITE_FAILED;
        event.severity = vhsm::notification::NotificationEvent::Severity::CRITICAL;
        event.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        event.source = "slot:" + std::to_string(slot_id) + "/token:" + token_label;
        event.actor = user_label.value_or("UNKNOWN");
        event.summary = "Failed to write signature record to DB";
        event.detail_json = "{}"; // TODO: include more details
        event.hsm_instance = ""; // TODO: fetch from db_meta
        notification_bus_.publish(event);
        return;
    }
    std::string signature_id = *signature_id_opt;

    // Log to audit log
    audit_log_.append(signature_id, "C_SIGN");

    // Publish SIGN_CREATED notification
    vhsm::notification::NotificationEvent sign_event;
    sign_event.type = vhsm::notification::NotificationEvent::EventType::SIGN_CREATED;
    sign_event.severity = vhsm::notification::NotificationEvent::Severity::INFO;
    sign_event.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    sign_event.source = "slot:" + std::to_string(slot_id) + "/token:" + token_label;
    sign_event.actor = user_label.value_or("UNKNOWN");
    sign_event.summary = "Signature " + signature_id.substr(0, 8) + "... created for key " + key_id;
    // Build detail JSON
    std::stringstream detail_ss;
    detail_ss << R"({"signature_id":") << signature_id << R"(",)"
              << R"("key_fingerprint":") << key_fingerprint << R"(",)"
              << R"("payload_digest":") << payload_digest << R"(",)"
              // No ledger info yet
              << R"("ledger_tx_id":"")"
              << R"(",)"
              << R"("ledger_block_num":0)";
    sign_event.detail_json = detail_ss.str();
    sign_event.hsm_instance = ""; // TODO: fetch from db_meta
    notification_bus_.publish(sign_event);

    // Asynchronously submit to ledger will be handled in Phase 5 by the ledger worker.
    // For Phase 4, we just leave the ledger fields empty and they will be updated later.
}

}  // namespace db
}  // namespace vhsm::signature_store