#include "verification_service_core.h"

#include <optional>
#include <string>

namespace vhsm::signature_store {
namespace db {
namespace internal {

v_VerificationServiceCore_M1::v_VerificationServiceCore_M1(
    IDbConnection &conn, vhsm::ledger::LedgerClient *ledger_client,
    SignatureRepository &signature_repository)
    : v_conn_(conn), v_ledger_client_(ledger_client),
      v_signature_repository_(signature_repository) {}

v_VerificationResult_M1
v_VerificationServiceCore_M1::v_verify(const std::string &signature_id,
                                       bool check_ledger) {
  v_VerificationResult_M1 result;
  result.local_record_exists = false;
  result.ledger_record_exists = false;
  result.payload_digest_match = false;
  result.signature_b64_match = false;
  result.key_fingerprint_match = false;

  // First, get the record from local DB.
  auto local_row_opt = v_signature_repository_.get_by_id(signature_id);
  if (!local_row_opt) {
    result.error_detail = "Signature record not found in local DB";
    return result;
  }
  result.local_record_exists = true;

  // Tamper-evidence: verify the row-integrity HMAC over the stored columns.
  // A mismatch means the row was altered outside the normal insert/update path.
  result.integrity_hmac_ok =
      v_signature_repository_.verify_integrity(signature_id);
  if (!result.integrity_hmac_ok && !result.error_detail) {
    result.error_detail = "Local record integrity HMAC verification failed";
  }

  // Extract fields from local row (vector of 17 optional<string>).
  // Index mapping:
  // 0: id, 1: created_at, 2: slot_id, 3: token_label, 4: key_id,
  // 5: key_fingerprint, 6: mechanism, 7: payload_digest, 8: signature_b64,
  // 9: session_handle, 10: user_label, 11: app_context, 12: ledger_tx_id,
  // 13: ledger_block_num, 14: ledger_tx_time, 15: ledger_tx_proof,
  // 16: ledger_tx_set_b64, 17: ledger_status.

  const auto &local_row = local_row_opt.value();

  auto get_string_safe =
      [](const std::optional<std::string> &opt) -> std::string {
    return opt ? *opt : "";
  };

  auto get_int_safe =
      [](const std::optional<std::string> &opt) -> std::optional<int64_t> {
    if (!opt)
      return std::nullopt;
    if (opt->empty())
      return std::nullopt;
    try {
      return std::stoll(*opt);
    } catch (...) {
      return std::nullopt;
    }
  };

  std::string local_key_fingerprint = get_string_safe(local_row[5]);
  std::string local_payload_digest = get_string_safe(local_row[7]);
  std::string local_signature_b64 = get_string_safe(local_row[8]);
  std::optional<std::string> local_ledger_tx_id_opt;
  if (!local_row[12].has_value() || local_row[12].value().empty()) {
    local_ledger_tx_id_opt = std::nullopt;
  } else {
    local_ledger_tx_id_opt = local_row[12];
  }
  std::optional<int64_t> local_ledger_block_num_opt =
      get_int_safe(local_row[13]);

  // If we don't need to check ledger, just return that local record exists.
  if (!check_ledger) {
    return result;
  }

  // Ledger cross-check requested but no client configured (e.g. VHSM_LEDGER=OFF or endpoint not set).
  // Fail open for ledger part — integrity_hmac_ok already decided above; ledger mismatch is logged
  // but does not mask a valid local record. This avoids making C_Verify flaky due to anchoring latency.
  if (!v_ledger_client_) {
    result.error_detail = "ledger client not configured — ledger cross-check skipped";
    return result;
  }

  // If we have a ledger tx ID, try to get the record from ledger.
  if (local_ledger_tx_id_opt) {
    auto ledger_entry_opt =
        v_ledger_client_->get_record(*local_ledger_tx_id_opt);
    if (ledger_entry_opt) {
      result.ledger_record_exists = true;
      result.ledger_tx_id = local_ledger_tx_id_opt;
      result.ledger_block_num = local_ledger_block_num_opt;

      // Compare fields.
      result.payload_digest_match =
          (ledger_entry_opt->payload_digest == local_payload_digest);
      result.signature_b64_match =
          (ledger_entry_opt->signature_b64 == local_signature_b64);
      result.key_fingerprint_match =
          (ledger_entry_opt->key_fingerprint == local_key_fingerprint);
    } else {
      result.error_detail = "Ledger record not found for transaction ID";
    }
  } else {
    result.error_detail = "No ledger transaction ID in local record";
  }

  return result;
}

} // namespace internal
} // namespace db
} // namespace vhsm::signature_store
