#include "signature_dispatcher_core.h"

#include "../../core/hsm_instance.h"
#include "../../core/utils.h"

#include <chrono>
#include <sstream>

namespace vhsm::signature_store {
namespace db {
namespace internal {

v_SignatureDispatcherCore_M1::v_SignatureDispatcherCore_M1(
    IDbConnection &conn, vhsm::keystore::Token &token,
    vhsm::notification::NotificationBus &notification_bus,
    vhsm::audit::AuditLog &audit_log, vhsm::ledger::LedgerWorker *ledger_worker,
    const IHsmClock &clock)
    : v_conn_(conn), v_signature_repository_(conn, token),
      v_notification_bus_(notification_bus), v_audit_log_(audit_log),
      v_ledger_worker_(ledger_worker), v_clock_(clock) {}

bool v_SignatureDispatcherCore_M1::v_dispatch(
    const v_SignatureDispatchInput_M1 &input) {
  std::string payload_digest =
      input.sign_result.payload_digest; // already hex string
  std::string signature_b64 = vhsm::utils::base64_encode(
      std::span<const std::byte>(reinterpret_cast<const std::byte *>(
                                     input.sign_result.signature.data()),
                                 input.sign_result.signature.size()));

  // Persist the signature record transactionally with outbox event.
  // The outbox pattern ensures that DB commit and event publishing are atomic:
  // the SIGN_CREATED event is inserted into event_outbox in the same DB
  // transaction as the signature record, so a crash between DB commit and bus
  // publish does not lose the event — the poller will replay it.
  std::string signature_id;
  bool inserted = false;
  try {
    v_conn_.with_transaction([&](IDbTransaction &tx) {
      // Insert signature via repository's SQL directly on the transaction to
      // keep both writes atomic. We replicate the repository's insert logic
      // here to avoid a second round-trip; the repository remains the
      // single source of SQL for non-transactional callers.
      signature_id = vhsm::utils::uuid_v4();
      std::vector<std::string> cols = {signature_id,
                                       std::to_string(input.created_at),
                                       std::to_string(input.slot_id),
                                       input.token_label,
                                       input.key_id,
                                       input.key_fingerprint,
                                       input.mechanism,
                                       payload_digest,
                                       signature_b64,
                                       input.session_handle,
                                       input.user_label.value_or(""),
                                       input.app_context.value_or(""),
                                       "",
                                       "0",
                                       "",
                                       "",
                                       "",
                                       "PENDING"};
      const std::string sql_sig = R"SQL(
        INSERT INTO signature_records (
            id, created_at, slot_id, token_label, key_id, key_fingerprint,
            mechanism, payload_digest, signature_b64, session_handle,
            user_label, app_context,
            ledger_tx_id, ledger_block_num, ledger_tx_time, ledger_tx_proof,
            ledger_tx_set_b64, ledger_status
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);
      )SQL";
      tx.exec(sql_sig, cols);

      // Outbox event for SIGN_CREATED — will be dispatched by the poller.
      std::string outbox_id = vhsm::utils::uuid_v4();
      std::string payload = R"({"signature_id":")" + signature_id +
                            R"(","key_id":")" + input.key_id + R"("})";
      tx.exec(
          R"SQL(INSERT INTO event_outbox (id, created_at, event_type, aggregate_id, payload, status) VALUES (?,?,?,?,?,?);)SQL",
          {outbox_id, std::to_string(v_clock_.now().time_since_epoch().count()),
           "SIGN_CREATED", signature_id, payload, "PENDING"});
      inserted = true;
    });
  } catch (...) {
    inserted = false;
  }

  if (!inserted) {
    // Transaction rolled back, so outbox event was not written either.
    // Publish a best-effort DB_WRITE_FAILED directly (not via outbox,
    // because the DB itself failed).
    vhsm::notification::NotificationEvent event;
    event.type =
        vhsm::notification::NotificationEvent::EventType::DB_WRITE_FAILED;
    event.severity = vhsm::notification::NotificationEvent::Severity::CRITICAL;
    event.timestamp = v_clock_.now().time_since_epoch().count();
    event.source =
        "slot:" + std::to_string(input.slot_id) + "/token:" + input.token_label;
    event.actor = input.user_label.value_or("UNKNOWN");
    event.summary = "Failed to write signature record to DB";
    event.detail_json = "{}";
    event.hsm_instance = vhsm::core::hsm_instance_id();
    v_notification_bus_.publish(event);
    return false;
  }

  // WHY no direct publish/ledger submit here: The SIGN_CREATED notification
  // and the ledger anchor are now written to `event_outbox` inside the same
  // DB transaction above. A crash between DB commit and bus publish no longer
  // loses the event — the `OutboxPoller` (or `LedgerRetryQueue` for ledger)
  // replays `PENDING` rows on the next `C_Initialize` or poll interval. Direct
  // `v_notification_bus_.publish` and `v_ledger_worker_->submit_record` are
  // intentionally removed; the poller is the single writer to the bus/ledger.
  // For backward compat, `C_Sign` still returns `CKR_OK` as soon as the
  // transaction commits (latency not blocked on Fabric).
  return true;
}

} // namespace internal
} // namespace db
} // namespace vhsm::signature_store
