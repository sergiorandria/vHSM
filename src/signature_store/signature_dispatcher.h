#ifndef VHSM_SIGSTORE_SIGNATURE_DISPATCHER_H
#define VHSM_SIGSTORE_SIGNATURE_DISPATCHER_H

#include <optional>
#include <string>

#include "../audit/audit_log.h"
#include "../core/system_hsm_clock.h"
#include "../core/types.h"
#include "../keystore/token.h"
#include "../ledger/ledger_worker.h"
#include "../notification/notification_bus.h"
#include "db_connection.h"
#include "internal/signature_dispatcher_core.h"

namespace vhsm::signature_store {
namespace db {

// WHY SignatureDispatcher is a public facade: PKCS#11 signing flows through
// CryptoEngine, which returns a SignResult (signature bytes + mechanism +
// digest). SignatureDispatcher takes that result and orchestrates the
// persistence/audit/notification/ledger workflow:
//   1. Persist to database (SignatureRepository)
//   2. Log to audit log (AuditLog)
//   3. Publish event (NotificationBus)
//   4. Queue for ledger (LedgerWorker) — asynchronous blockchain anchoring
//
// WHY signature store is complex: Blockchain integration is
// eventual-consistent. A signature is created locally (database), then
// asynchronously committed to the ledger. If the ledger fails, retry queues
// hold the entry until success. The dispatcher manages this state machine.
//
// WHY inject dependencies (clock, bus, audit_log, ledger_worker): Decouples
// signature storage from specific implementations. Production uses real
// database/ledger; tests can mock them. Dependency injection enables testing
// without blockchain or database setup.
//
// WHY dispatch method is the single orchestration point: All signatures flow
// through this method. Centralizes policy:
//   - What gets persisted (all fields)
//   - What gets audited (user_label, mechanism, key_id)
//   - What gets notified (severity based on success/failure)
//   - What gets ledger-committed (cryptographic proof)
// This prevents bypasses and ensures consistency.

// WHY public facade + internal core pattern: Input validation and orchestration
// live in the facade (this class). The core owns database transactions, retry
// logic, and ledger state. This separation makes the facade testable (mock the
// core) and the core auditable (no C API).

class SignatureDispatcher {
public:
  // WHY constructor takes multiple dependencies: All are required for dispatch
  // to work.
  // - conn: database connection (persist the signature)
  // - token: keystore token (verify key exists, wrap if needed)
  // - notification_bus: event publisher (notify subscribers)
  // - audit_log: audit trail (record who signed what)
  // - ledger_worker: optional ledger submitter (async blockchain commit,
  // nullptr = skip ledger)
  SignatureDispatcher(IDbConnection &conn, vhsm::keystore::Token &token,
                      vhsm::notification::NotificationBus &notification_bus,
                      vhsm::audit::AuditLog &audit_log,
                      vhsm::ledger::LedgerWorker *ledger_worker = nullptr);

  // WHY dispatch is the single public method: Centralizes the entire signing
  // workflow. Takes a SignResult (from CryptoEngine) and contextual metadata,
  // then orchestrates:
  //   1. Wrap the signature (if needed) with the token's KEK
  //   2. Persist to database as a SignatureRecord
  //   3. Log to audit log (user_label, mechanism, success/failure)
  //   4. Publish notification (severity = CRITICAL on failure, INFO on success)
  //   5. Queue to ledger worker for asynchronous blockchain commit
  // Returns true on success, false if the DB write failed (fail-closed).
  bool dispatch(const vhsm::crypto::SignResult &sign_result, int64_t created_at,
                int slot_id, const std::string &token_label,
                const std::string &key_id, const std::string &key_fingerprint,
                const std::string &mechanism,
                const std::string &digest_algorithm,
                const std::string &session_handle,
                const std::optional<std::string> &user_label,
                const std::optional<std::string> &app_context);

private:
  // WHY SystemHsmClock: Injected for testability. Records creation timestamps
  // for audit. Tests inject FrozenHsmClock; production uses system time.
  vhsm::SystemHsmClock v_clock_;

  // WHY internal core: All state management, transactions, and ledger logic.
  vhsm::signature_store::db::internal::v_SignatureDispatcherCore_M1 v_core_;
};

} // namespace db
} // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_SIGNATURE_DISPATCHER_H
