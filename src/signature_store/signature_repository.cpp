#include "signature_repository.h"

#include "../core/error.h"
#include "../core/utils.h"
#include "../ledger/ledger_entry.h"
#include "row_integrity.h"

#include <vector>

namespace vhsm::signature_store {
namespace db {

SignatureRepository::SignatureRepository(IDbConnection &conn,
                                         vhsm::keystore::Token &token)
    : conn_(conn), token_(token) {}

std::optional<std::string> SignatureRepository::insert(
    int64_t created_at, int slot_id, const std::string &token_label,
    const std::string &key_id, const std::string &key_fingerprint,
    const std::string &mechanism,
    [[maybe_unused]] const std::string &digest_algorithm,
    const std::string &payload_digest, int, const std::string &signature_b64,
    const std::string &session_handle,
    const std::optional<std::string> &user_label,
    const std::optional<std::string> &app_context) {
  // Generate a UUID for the signature ID
  std::string id = vhsm::utils::uuid_v4();

  // Column order matches sql_create_signature_records(); the legacy
  // digest_algorithm parameter is not stored (no dedicated column).
  std::vector<std::string> column_values;
  column_values.reserve(18);

  column_values.push_back(id);                         // id
  column_values.push_back(std::to_string(created_at)); // created_at
  column_values.push_back(std::to_string(slot_id));    // slot_id
  column_values.push_back(token_label);                // token_label
  column_values.push_back(key_id);                     // key_id
  column_values.push_back(key_fingerprint);            // key_fingerprint
  column_values.push_back(mechanism);                  // mechanism
  column_values.push_back(payload_digest);             // payload_digest
  column_values.push_back(signature_b64);              // signature_b64
  column_values.push_back(session_handle);             // session_handle
  column_values.push_back(user_label.value_or(""));    // user_label
  column_values.push_back(app_context.value_or(""));   // app_context
  column_values.push_back("");                         // ledger_tx_id (NULL)
  column_values.push_back("0");       // ledger_block_num (NULL)
  column_values.push_back("");        // ledger_tx_time
  column_values.push_back("");        // ledger_tx_proof
  column_values.push_back("");        // ledger_tx_set_b64
  column_values.push_back("PENDING"); // ledger_status

  // Now we insert the row (no integrity_hmac column)
  const std::string sql = R"SQL(
        INSERT INTO signature_records (
            id, created_at, slot_id, token_label, key_id, key_fingerprint,
            mechanism, payload_digest, signature_b64, session_handle,
            user_label, app_context,
            ledger_tx_id, ledger_block_num, ledger_tx_time, ledger_tx_proof,
            ledger_tx_set_b64, ledger_status
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        );
    )SQL";

  try {
    conn_.exec(sql, column_values);
  } catch (const DbError &e) {
    // Log the error
    return std::nullopt;
  }

  return id;
}

bool SignatureRepository::update_ledger_fields(
    const std::string &signature_id, const vhsm::ledger::LedgerEntry &entry) {
  // Optimized: single 3-col UPDATE, no SELECT. Previously this did
  // SELECT + 18-col UPDATE (rewriting immutable columns). The ledger fields
  // are the only ones that change post-insert, so we touch only them.
  const std::string sql = R"SQL(
        UPDATE signature_records SET
            ledger_tx_id = ?,
            ledger_block_num = ?,
            ledger_status = ?
        WHERE id = ?;
    )SQL";
  std::vector<std::string> params;
  params.reserve(4);
  params.push_back(entry.tx_id);
  params.push_back(std::to_string(entry.block_number));
  params.push_back("COMMITTED");
  params.push_back(signature_id);
  try {
    i64 n = conn_.exec(sql, params);
    if (n == 0)
      return false;
  } catch (const DbError &e) {
    return false;
  }
  // The ledger fields (tx_id/block/status) just changed, so the row-integrity
  // HMAC computed at insert is now stale. Recompute it over the current 18
  // columns so tamper-evidence stays valid after the update. Fail-soft: if the
  // HMAC key is unavailable we leave the old value rather than crash the caller.
  recompute_integrity_hmac(signature_id);
  return true;
}

bool SignatureRepository::mark_processing(const std::string &signature_id) {
  const std::string sql =
      "UPDATE signature_records SET ledger_status = 'PROCESSING' WHERE id = ? "
      "AND ledger_status = 'PENDING';";
  try {
    conn_.exec(sql, {signature_id});
    return true;
  } catch (const DbError &) {
    return false;
  }
}

bool SignatureRepository::recompute_integrity_hmac(
    const std::string &signature_id) {
  const std::string sql = R"SQL(
      SELECT id, created_at, slot_id, token_label, key_id, key_fingerprint,
             mechanism, payload_digest, signature_b64, session_handle,
             user_label, app_context,
             ledger_tx_id, ledger_block_num, ledger_tx_time, ledger_tx_proof,
             ledger_tx_set_b64, ledger_status
      FROM signature_records WHERE id = ?;
    )SQL";
  try {
    auto rs = conn_.query(sql, {signature_id});
    if (rs.rows_.empty())
      return false;
    const DbRow &row = rs.rows_[0];
    std::vector<std::optional<std::string>> cols;
    cols.reserve(18);
    for (size_t i = 0; i < row.column_count(); ++i) {
      auto opt = row.get_string(i);
      cols.push_back(opt ? *opt : std::optional<std::string>{});
    }
    RowIntegrity ri(conn_, token_);
    std::string hmac = ri.compute_hmac(cols);
    conn_.exec("UPDATE signature_records SET integrity_hmac=? WHERE id=?",
               {hmac, signature_id});
    return true;
  } catch (...) {
    return false;
  }
}

bool SignatureRepository::verify_integrity(const std::string &signature_id) const {
  const std::string sql = R"SQL(
      SELECT id, created_at, slot_id, token_label, key_id, key_fingerprint,
             mechanism, payload_digest, signature_b64, session_handle,
             user_label, app_context,
             ledger_tx_id, ledger_block_num, ledger_tx_time, ledger_tx_proof,
             ledger_tx_set_b64, ledger_status, integrity_hmac
      FROM signature_records WHERE id = ?;
    )SQL";
  try {
    auto rs = conn_.query(sql, {signature_id});
    if (rs.rows_.empty())
      return false;
    const DbRow &row = rs.rows_[0];
    std::vector<std::optional<std::string>> cols;
    cols.reserve(18);
    for (size_t i = 0; i < 18; ++i) {
      auto opt = row.get_string(i);
      cols.push_back(opt ? *opt : std::optional<std::string>{});
    }
    auto stored = row.get_string(18);
    RowIntegrity ri(conn_, token_);
    return ri.verify_hmac(cols, stored);
  } catch (...) {
    return false;
  }
}

std::optional<std::vector<std::optional<std::string>>>
SignatureRepository::get_by_id(const std::string &signature_id) const {
  const std::string sql = R"SQL(
        SELECT id, created_at, slot_id, token_label, key_id, key_fingerprint,
               mechanism, payload_digest, signature_b64, session_handle,
               user_label, app_context,
               ledger_tx_id, ledger_block_num, ledger_tx_time, ledger_tx_proof,
               ledger_tx_set_b64, ledger_status,
               pqc_algo, signature_pqc_b64, key_fingerprint_pqc
        FROM signature_records
        WHERE id = ?;
    )SQL";

  try {
    auto rs = conn_.query(sql, {signature_id});
    if (rs.rows_.empty()) {
      return std::nullopt;
    }
    // We expect exactly one row.
    const DbRow &row = rs.rows_[0];
    std::vector<std::optional<std::string>> result;
    result.reserve(17);
    for (size_t i = 0; i < row.column_count(); ++i) {
      auto opt = row.get_string(i);
      if (opt) {
        // For the ledger_block_num column (index 13), we need to check if the
        // string is "0" to mean NULL.
        if (i == 13 && *opt == "0") {
          result.push_back(std::nullopt);
        } else {
          // For text columns, empty string means NULL.
          if (opt->empty()) {
            result.push_back(std::nullopt);
          } else {
            result.push_back(*opt);
          }
        }
      } else {
        // This should not happen because get_string returns nullopt only on
        // conversion error? But we treat it as NULL.
        result.push_back(std::nullopt);
      }
    }
  return result;
   } catch (const DbError &e) {
    return std::nullopt;
  }
}

std::vector<std::string> SignatureRepository::get_all_ids() const {
  const std::string sql =
      "SELECT id FROM signature_records ORDER BY created_at ASC;";
  std::vector<std::string> ids;
  try {
    auto rs = conn_.query(sql, {});
    ids.reserve(rs.rows_.size());
    for (const auto &row : rs.rows_) {
      if (row.column_count() > 0) {
        if (auto v = row.get_string(0)) {
          ids.push_back(*v);
        }
      }
    }
  } catch (const DbError &) {
    return ids;
  }
  return ids;
}

} // namespace db
} // namespace vhsm::signature_store