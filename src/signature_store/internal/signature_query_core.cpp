#include "signature_query_core.h"

#include "../../core/error.h"
#include "verification_service_core.h"

#include <vector>

namespace vhsm::signature_store {
namespace db {
namespace internal {

namespace {

// SignatureRecord row column order (matches sql_create_signature_records()).
enum Column : std::size_t {
  kId = 0,
  K_CREATED_AT,
  kSlotId,
  kTokenLabel,
  kKeyId,
  kKeyFingerprint,
  kMechanism,
  kPayloadDigest,
  kSignatureB64,
  kSessionHandle,
  kUserLabel,
  kAppContext,
  kLedgerTxId,
  kLedgerBlockNum,
  kLedgerTxTime,
  kLedgerTxProof,
  kLedgerTxSetB64,
  kLedgerStatus,
  kColumnCount,
};

std::string to_string_safe(const std::optional<std::string> &opt) {
  return opt ? *opt : "";
}

} // namespace

v_SignatureQueryCore_M1::v_SignatureQueryCore_M1(IDbConnection &conn,
                                                 vhsm::keystore::Token &token)
    : v_conn_(conn), v_signature_repository_(conn, token) {}

std::optional<std::vector<std::optional<std::string>>>
v_SignatureQueryCore_M1::v_get_signature_by_id(
    const std::string &signature_id) const {
  return v_signature_repository_.get_by_id(signature_id);
}

v_SignatureQueryVerificationResult_M1
v_SignatureQueryCore_M1::v_verify_signature(
    const std::string &signature_id) const {
  // Consolidated: single implementation is VerificationService (row-integrity HMAC + ledger).
  // This wrapper exists for backward compat and pure lookups; verification now forwards to
  // VerificationService so there is exactly one code path for "is this record trustworthy?".
  // See docs/ARCHITECTURE_REVIEW.md and verification_service_core.cpp.
  v_VerificationServiceCore_M1 svc(
      const_cast<IDbConnection &>(v_conn_),
      nullptr, const_cast<SignatureRepository &>(v_signature_repository_));
  auto vres = svc.v_verify(signature_id, /*check_ledger=*/false);
  v_SignatureQueryVerificationResult_M1 result;
  result.record_found = vres.local_record_exists;
  // Map integrity failure to ledger_cross_check_ok=false so callers fail closed
  if (!vres.integrity_hmac_ok && vres.local_record_exists) {
    result.error_detail = vres.error_detail ? *vres.error_detail
                                            : "Local record integrity HMAC verification failed";
    result.ledger_cross_check_ok = false;
    // Still expose ledger_status/tx for debugging, even when HMAC fails
    if (vres.ledger_tx_id) result.ledger_tx_id = *vres.ledger_tx_id;
    if (vres.ledger_block_num) result.ledger_block_num = *vres.ledger_block_num;
    // Try to get ledger_status from local row for backward compat
    auto row_opt = v_signature_repository_.get_by_id(signature_id);
    if (row_opt && row_opt->size() > kLedgerStatus) {
      result.ledger_status = to_string_safe((*row_opt)[kLedgerStatus]);
      result.payload_digest = to_string_safe((*row_opt)[kPayloadDigest]);
    }
    return result;
  }
  // No HMAC failure — map the rest from vres and local row
  if (vres.error_detail) result.error_detail = *vres.error_detail;
  if (vres.ledger_tx_id) result.ledger_tx_id = *vres.ledger_tx_id;
  if (vres.ledger_block_num) result.ledger_block_num = *vres.ledger_block_num;
  auto row_opt = v_signature_repository_.get_by_id(signature_id);
  if (row_opt && row_opt->size() >= kColumnCount) {
    result.record_found = true;
    result.payload_digest = to_string_safe((*row_opt)[kPayloadDigest]);
    result.ledger_status = to_string_safe((*row_opt)[kLedgerStatus]);
    // Original SignatureQuery local-only check was ledger_status=="COMMITTED"
    // Keep that for backward compat when check_ledger==false, but now HMAC is already verified above.
    result.ledger_cross_check_ok = (result.ledger_status == "COMMITTED");
  } else if (vres.local_record_exists) {
    result.record_found = true;
    result.ledger_status = "PENDING";
  }
  return result;
}

v_SignatureQueryVerificationResult_M1
v_SignatureQueryCore_M1::v_verify_signature(
    const std::string &signature_id, vhsm::ledger::LedgerClient &ledger) {
  // Forward to the single VerificationService implementation (HMAC + ledger)
  v_VerificationServiceCore_M1 svc(
      const_cast<IDbConnection &>(v_conn_),
      &ledger, const_cast<SignatureRepository &>(v_signature_repository_));
  auto vres = svc.v_verify(signature_id, /*check_ledger=*/true);
  v_SignatureQueryVerificationResult_M1 result;
  result.record_found = vres.local_record_exists;
  // Map integrity failure
  if (!vres.integrity_hmac_ok && vres.local_record_exists) {
    result.error_detail = vres.error_detail ? *vres.error_detail
                                            : "Local record integrity HMAC verification failed";
    result.ledger_cross_check_ok = false;
    if (vres.ledger_tx_id) result.ledger_tx_id = *vres.ledger_tx_id;
    if (vres.ledger_block_num) result.ledger_block_num = *vres.ledger_block_num;
    auto row_opt = v_signature_repository_.get_by_id(signature_id);
    if (row_opt && row_opt->size() > kLedgerStatus) {
      result.ledger_status = to_string_safe((*row_opt)[kLedgerStatus]);
      result.payload_digest = to_string_safe((*row_opt)[kPayloadDigest]);
    }
    return result;
  }
  result.ledger_cross_check_ok = vres.ledger_record_exists &&
                               vres.payload_digest_match &&
                               vres.signature_b64_match &&
                               vres.key_fingerprint_match;
  if (vres.error_detail) result.error_detail = *vres.error_detail;
  if (vres.ledger_tx_id) result.ledger_tx_id = *vres.ledger_tx_id;
  if (vres.ledger_block_num) result.ledger_block_num = *vres.ledger_block_num;
  // ledger_status from local row for backward compat
  auto row_opt = v_signature_repository_.get_by_id(signature_id);
  if (row_opt && row_opt->size() > kLedgerStatus) {
    result.ledger_status = to_string_safe((*row_opt)[kLedgerStatus]);
    result.payload_digest = to_string_safe((*row_opt)[kPayloadDigest]);
  }
  return result;
}

std::vector<std::string>
v_SignatureQueryCore_M1::v_get_signature_ids_by_key_fingerprint(
    const std::string &key_fingerprint) {
  const std::string sql = R"SQL(
        SELECT id FROM signature_records WHERE key_fingerprint = ?;
    )SQL";
  try {
    auto rs = v_conn_.query(sql, {key_fingerprint});
    std::vector<std::string> ids;
    ids.reserve(rs.rows_.size());
    for (const auto &row : rs.rows_) {
      if (row.column_count() > 0 && row.get_string(0)) {
        ids.push_back(*row.get_string(0));
      }
    }
    return ids;
  } catch (const DbError &e) {
    return {};
  }
}

std::vector<std::string>
v_SignatureQueryCore_M1::v_get_signature_ids_by_time_range(int64_t start_time,
                                                           int64_t end_time) {
  const std::string sql = R"SQL(
        SELECT id FROM signature_records WHERE created_at >= ? AND created_at <= ?;
    )SQL";
  try {
    auto rs = v_conn_.query(
        sql, {std::to_string(start_time), std::to_string(end_time)});
    std::vector<std::string> ids;
    ids.reserve(rs.rows_.size());
    for (const auto &row : rs.rows_) {
      if (row.column_count() > 0 && row.get_string(0)) {
        ids.push_back(*row.get_string(0));
      }
    }
    return ids;
  } catch (const DbError &e) {
    return {};
  }
}

} // namespace internal
} // namespace db
} // namespace vhsm::signature_store
