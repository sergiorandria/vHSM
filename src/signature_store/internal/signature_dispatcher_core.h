#ifndef VHSM_SIGSTORE_INTERNAL_SIGNATURE_DISPATCHER_CORE_H
#define VHSM_SIGSTORE_INTERNAL_SIGNATURE_DISPATCHER_CORE_H

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "../../core/types.h"
#include "../../core/hsm_clock.h"
#include "../db_connection.h"
#include "../signature_repository.h"
#include "../../keystore/token.h"
#include "../../notification/notification_bus.h"
#include "../../notification/notification_event.h"
#include "../../audit/audit_log.h"
#include "../../ledger/ledger_worker.h"

namespace vhsm::signature_store {
namespace db {
namespace internal {

// Internal representation of a dispatch request.  The public facade fills this
// in after validating user input; the core owns all persistence, audit,
// notification and ledger-anchoring logic.
struct v_SignatureDispatchInput_M1 {
    vhsm::crypto::SignResult sign_result;
    int64_t                  created_at;
    int                      slot_id;
    std::string              token_label;
    std::string              key_id;
    std::string              key_fingerprint;
    std::string              mechanism;
    std::string              digest_algorithm;
    std::string              session_handle;
    std::optional<std::string> user_label;
    std::optional<std::string> app_context;
};

// Core business logic behind SignatureDispatcher.  Holds no validation
// responsibility; it assumes the input has already been vetted by the facade.
class v_SignatureDispatcherCore_M1 {
public:
    v_SignatureDispatcherCore_M1(
        IDbConnection& conn,
        vhsm::keystore::Token& token,
        vhsm::notification::NotificationBus& notification_bus,
        vhsm::audit::AuditLog& audit_log,
        vhsm::ledger::LedgerWorker* ledger_worker,
        const IHsmClock& clock);

    void v_dispatch(const v_SignatureDispatchInput_M1& input);

private:
    IDbConnection& v_conn_;
    SignatureRepository v_signature_repository_;
    vhsm::notification::NotificationBus& v_notification_bus_;
    vhsm::audit::AuditLog& v_audit_log_;
    vhsm::ledger::LedgerWorker* v_ledger_worker_;
    const IHsmClock& v_clock_;
};

}  // namespace internal
}  // namespace db
}  // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_INTERNAL_SIGNATURE_DISPATCHER_CORE_H
