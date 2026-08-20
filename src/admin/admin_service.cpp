#include "admin_service.h"

#include <chrono>
#include <sstream>

namespace vhsm::admin {

AdminLoginCore::AdminLoginCore(keystore::Token& token,
                               vhsm::notification::NotificationBus* bus,
                               vhsm::audit::AuditLog* audit_log)
    : token_(token), bus_(bus), audit_log_(audit_log) {}

CK_RV AdminLoginCore::admin_login(CK_USER_TYPE userType, const std::string& pin,
                                  const std::string& caller) {
    if (userType != CKU_USER && userType != CKU_SO) {
        return CKR_USER_TYPE_INVALID;
    }

    const CK_RV rv = token_.login(userType,
                                  reinterpret_cast<const CK_CHAR*>(pin.data()),
                                  static_cast<CK_ULONG>(pin.size()));
    if (rv != CKR_OK) {
        return rv;
    }

    // Success: publish ADMIN_LOGIN (INFO) so subscribers (audit trail, SIEM,
    // webhooks) see that an administrative identity authenticated.
    if (bus_ && audit_log_) {
        const int64_t created_at = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        vhsm::notification::NotificationEvent event;
        event.type = vhsm::notification::NotificationEvent::EventType::ADMIN_LOGIN;
        event.severity = vhsm::notification::NotificationEvent::Severity::INFO;
        event.timestamp = created_at;
        event.source = "admin";
        event.actor = caller.empty() ? (userType == CKU_SO ? "SO" : "USER") : caller;
        event.summary = std::string(userType == CKU_SO ? "SO" : "USER") +
                        " authenticated via gRPC admin on token " + token_.get_label();
        std::stringstream detail_ss;
        detail_ss << R"({"token":")" << token_.get_id()
                  << R"(","role":")" << (userType == CKU_SO ? "SO" : "USER")
                  << R"(","caller":")" << caller << R"("})";
        event.detail_json = detail_ss.str();
        event.hsm_instance = "";  // TODO: fetch from db_meta

        bus_->publish(event);
        audit_log_->append("ADMIN_LOGIN-" + std::to_string(created_at), "ADMIN_LOGIN");
    }

    return CKR_OK;
}

}  // namespace vhsm::admin