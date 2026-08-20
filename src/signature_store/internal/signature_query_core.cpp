#include "signature_query_core.h"

#include "../../core/error.h"

#include <vector>

namespace vhsm::signature_store {
namespace db {
namespace internal {

namespace {

// SignatureRecord row column order (matches sql_create_signature_records()).
enum Column : std::size_t {
  kId = 0,
  kCreatedAt,
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
  v_SignatureQueryVerificationResult_M1 result;
  auto row_opt = v_signature_repository_.get_by_id(signature_id);
  if (!row_opt) {
    result.error_detail = "Signature not found";
    return result;
  }
  const auto &row = *row_opt;
  if (row.size() < kColumnCount) {
    result.error_detail = "Corrupt signature row";
    return result;
  }

  result.record_found = true;
  result.payload_digest = to_string_safe(row[kPayloadDigest]);

  if (row[kLedgerTxId] && !row[kLedgerTxId]->empty()) {
    result.ledger_tx_id = *row[kLedgerTxId];
  }
  if (row[kLedgerBlockNum]) {
    try {
      result.ledger_block_num = std::stoll(*row[kLedgerBlockNum]);
    } catch (...) {
    }
  }
  result.ledger_status = to_string_safe(row[kLedgerStatus]);
  result.ledger_cross_check_ok = (result.ledger_status == "COMMITTED");

  return result;
}

v_SignatureQueryVerificationResult_M1
v_SignatureQueryCore_M1::v_verify_signature(
    const std::string &signature_id, vhsm::ledger::LedgerClient &ledger) {
  v_SignatureQueryVerificationResult_M1 result =
      v_verify_signature(signature_id);
  if (!result.record_found) {
    return result;
  }

  auto row_opt = v_signature_repository_.get_by_id(signature_id);
  if (!row_opt) {
    result.error_detail = "Signature not found";
    return result;
  }
  const auto &row = *row_opt;

  auto ledger_entry = ledger.get_record(signature_id);
  if (!ledger_entry) {
    result.error_detail = "Record not found on the Fabric ledger";
    result.ledger_cross_check_ok = false;
    return result;
  }

  // Cross-check the tamper-evident fields.
  const bool digest_ok =
      (ledger_entry->payload_digest == to_string_safe(row[kPayloadDigest]));
  const bool sig_ok =
      (ledger_entry->signature_b64 == to_string_safe(row[kSignatureB64]));
  const bool fingerprint_ok =
      (ledger_entry->key_fingerprint == to_string_safe(row[kKeyFingerprint]));

  result.ledger_cross_check_ok = digest_ok && sig_ok && fingerprint_ok;
  if (!result.ledger_cross_check_ok) {
    result.error_detail =
        "Ledger cross-check failed (digest/signature/fingerprint mismatch)";
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
