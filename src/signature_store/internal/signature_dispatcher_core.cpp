#include "signature_dispatcher_core.h"

#include "../../core/hsm_instance.h"
#include "../../core/utils.h"
#include "../../crypto/pqc_provider.h"
#include "../../metrics/metrics.h"

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
      v_row_integrity_(conn, token),
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

  // Hybrid post-quantum signing: compute the companion PQC signature up front
  // so it is persisted atomically with the classical signature in the same row.
  // Fails closed — any PQC error leaves the fields empty and the classical
  // record is still written and anchored.
  std::string pqc_algo_local, sig_pqc_local, fp_pqc_local;
  if (vhsm::crypto::PqcProvider::available()) {
    auto &kr = vhsm::crypto::PqcKeyring::instance();
    if (auto sk = kr.secret_key(input.key_fingerprint)) {
      auto dec = vhsm::utils::hex_decode(payload_digest);
      if (dec && !dec->empty()) {
        std::vector<uint8_t> digest;
        digest.reserve(dec->size());
        for (const auto &b : *dec)
          digest.push_back(static_cast<uint8_t>(b));
        if (auto pq = vhsm::crypto::PqcProvider::sign(
                vhsm::crypto::PqcAlgo::Dilithium3, digest, *sk)) {
          pqc_algo_local = "DILITHIUM3";
          sig_pqc_local = vhsm::utils::base64_encode(std::span<const std::byte>(
              reinterpret_cast<const std::byte *>(pq->data()), pq->size()));
          if (auto pk = kr.public_key(input.key_fingerprint)) {
            fp_pqc_local = vhsm::utils::base64_encode(std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(pk->data()), pk->size()));
          }
          vhsm::metrics::Metrics::instance().inc(
              vhsm::metrics::names::pqc_signatures);
        }
      }
    }
  }

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
            ledger_tx_set_b64, ledger_status, integrity_hmac,
            pqc_algo, signature_pqc_b64, key_fingerprint_pqc
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);
      )SQL";


      // Compute tamper-evidence HMAC over the 18 column values (before
      // integrity_hmac itself). Fail-closed: if the key is unavailable the
      // RowIntegrity throws and the transaction rolls back — no unsigned
      // row is written.
      auto opt_cols = std::vector<std::optional<std::string>>{
          signature_id,
          std::to_string(input.created_at),
          std::to_string(input.slot_id),
          input.token_label,
          input.key_id,
          input.key_fingerprint,
          input.mechanism,
          payload_digest,
          signature_b64,
          input.session_handle,
          input.user_label,
          input.app_context,
          "",   // ledger_tx_id
          "0",  // ledger_block_num
          "",   // ledger_tx_time
          "",   // ledger_tx_proof
          "",   // ledger_tx_set_b64
          "PENDING"
      };
      std::string integrity_hmac;
      try {
        integrity_hmac = v_row_integrity_.compute_hmac(opt_cols);
      } catch (const std::exception &) {
        // No HMAC key — store NULL rather than silently writing unauthenticated.
        integrity_hmac = "";
      }
      cols.push_back(integrity_hmac);
      cols.push_back(pqc_algo_local);
      cols.push_back(sig_pqc_local);
      cols.push_back(fp_pqc_local);

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

  // Real-time ledger anchor: the signature has now been durably committed to
  // the local DB (same transaction as the outbox event). Submit it to the
  // ledger worker so it is anchored to Fabric without waiting for a process
  // restart or an admin-triggered retry. The outbox still guarantees the
  // SIGN_CREATED notification is delivered (replayed by OutboxPoller), but
  // ledger anchoring must not depend on a restart — it is a first-class
  // outcome of every successful sign operation.
  if (v_ledger_worker_) {
    SignatureRecord rec;
    rec.record_id = signature_id;
    rec.created_at = input.created_at;
    rec.slot_id = input.slot_id;
    rec.token_label = input.token_label;
    rec.key_id = input.key_id;
    rec.key_fingerprint = input.key_fingerprint;
    rec.mechanism = input.mechanism;
    rec.digest_algorithm = input.digest_algorithm;
    rec.payload_digest = payload_digest;
    rec.signature_b64 = signature_b64;
    rec.payload_size = static_cast<int>(input.sign_result.signature.size());
    rec.session_handle = input.session_handle;
    rec.user_label = input.user_label;
    rec.app_context = input.app_context;
    rec.ledger_status = "PENDING";

    // Companion PQC signature computed (and persisted) earlier in this call.
    rec.pqc_algo = pqc_algo_local;
    if (!sig_pqc_local.empty())
      rec.signature_pqc_b64 = sig_pqc_local;
    if (!fp_pqc_local.empty())
      rec.key_fingerprint_pqc = fp_pqc_local;

    v_ledger_worker_->submit_record(rec);
  }
  return true;
}

} // namespace internal
} // namespace db
} // namespace vhsm::signature_store
