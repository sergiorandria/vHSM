#include "signature_dispatcher_core.h"

#include "../../core/utils.h"

#include <chrono>
#include <sstream>

namespace vhsm::signature_store {
namespace db {
namespace internal {

v_SignatureDispatcherCore_M1::v_SignatureDispatcherCore_M1(
    IDbConnection& conn,
    vhsm::keystore::Token& token,
    vhsm::notification::NotificationBus& notification_bus,
    vhsm::audit::AuditLog& audit_log,
    vhsm::ledger::LedgerWorker* ledger_worker,
    const IHsmClock& clock)
   : v_conn_(conn),
     v_signature_repository_(conn, token),
     v_notification_bus_(notification_bus),
     v_audit_log_(audit_log),
     v_ledger_worker_(ledger_worker),
     v_clock_(clock) {
}

    bool v_SignatureDispatcherCore_M1::v_dispatch(
    const v_SignatureDispatchInput_M1& input) {
    std::string payload_digest = input.sign_result.payload_digest;  // already hex string
    std::string signature_b64 = vhsm::utils::base64_encode(
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(input.sign_result.signature.data()),
            input.sign_result.signature.size()));

    // Persist the signature record.
    auto signature_id_opt = v_signature_repository_.insert(
        input.created_at,
        input.slot_id,
        input.token_label,
        input.key_id,
        input.key_fingerprint,
        input.mechanism,
        input.digest_algorithm,
        payload_digest,
        static_cast<int>(input.sign_result.signature.size()),  // payload_size
        signature_b64,
        input.session_handle,
        input.user_label,
        input.app_context);

    if (!signature_id_opt) {
        // If we cannot persist to DB, publish a DB_WRITE_FAILED notification.
        vhsm::notification::NotificationEvent event;
        event.type = vhsm::notification::NotificationEvent::EventType::DB_WRITE_FAILED;
        event.severity = vhsm::notification::NotificationEvent::Severity::CRITICAL;
        event.timestamp = v_clock_.now().time_since_epoch().count();
        event.source = "slot:" + std::to_string(input.slot_id) + "/token:" + input.token_label;
        event.actor = input.user_label.value_or("UNKNOWN");
        event.summary = "Failed to write signature record to DB";
        event.detail_json = "{}";  // TODO: include more details
        event.hsm_instance = "";   // TODO: fetch from db_meta
        v_notification_bus_.publish(event);
        return false;
    }
    std::string signature_id = *signature_id_opt;

    // Log to audit log.
    v_audit_log_.append(signature_id, "C_SIGN");

    // Publish SIGN_CREATED notification.
    vhsm::notification::NotificationEvent sign_event;
    sign_event.type = vhsm::notification::NotificationEvent::EventType::SIGN_CREATED;
    sign_event.severity = vhsm::notification::NotificationEvent::Severity::INFO;
    sign_event.timestamp = v_clock_.now().time_since_epoch().count();
    sign_event.source = "slot:" + std::to_string(input.slot_id) + "/token:" + input.token_label;
    sign_event.actor = input.user_label.value_or("UNKNOWN");
    sign_event.summary = "Signature " + signature_id.substr(0, 8) + "... created for key " + input.key_id;
    // Build detail JSON.
    std::stringstream detail_ss;
    detail_ss << R"({"signature_id":")" << signature_id << R"(",)"
              << R"("key_fingerprint":")" << input.key_fingerprint << R"(",)"
              << R"("payload_digest":")" << payload_digest << R"(",)"
              << R"("ledger_tx_id":"")"
              << R"(",)"
              << R"("ledger_block_num":0)";
    sign_event.detail_json = detail_ss.str();
    sign_event.hsm_instance = "";  // TODO: fetch from db_meta
    v_notification_bus_.publish(sign_event);

    // Asynchronously anchor the record on the Hyperledger Fabric ledger.  The
    // ledger worker submits RecordSignature and, on COMMITTED, fills in
    // ledger_tx_id / ledger_block_num and sets ledger_status='COMMITTED'.
    if (v_ledger_worker_) {
        SignatureRecord record;
        record.record_id          = signature_id;
        record.created_at         = input.created_at;
        record.slot_id            = input.slot_id;
        record.token_label        = input.token_label;
        record.key_id             = input.key_id;
        record.key_fingerprint    = input.key_fingerprint;
        record.mechanism          = input.mechanism;
        record.digest_algorithm   = input.digest_algorithm;
        record.payload_digest     = payload_digest;
        record.payload_size       = static_cast<int>(input.sign_result.signature.size());
        record.signature_b64      = signature_b64;
        record.session_handle     = input.session_handle;
        record.user_label         = input.user_label;
        record.app_context        = input.app_context;
        record.ledger_status      = "PENDING";
        v_ledger_worker_->submit_record(record);
    }
    return true;
}

}  // namespace internal
}  // namespace db
}  // namespace vhsm::signature_store
