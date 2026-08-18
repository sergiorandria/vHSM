#include "signature_repository.h"

#include "../core/error.h"
#include "../core/utils.h"
#include "../ledger/ledger_entry.h"


#include <vector>

namespace vhsm::signature_store {
namespace db {

SignatureRepository::SignatureRepository(IDbConnection& conn, vhsm::keystore::Token& token)
    : conn_(conn), token_(token) {}

std::optional<std::string> SignatureRepository::insert(
    int64_t created_at,
    int slot_id,
    const std::string& token_label,
    const std::string& key_id,
    const std::string& key_fingerprint,
    const std::string& mechanism,
    [[maybe_unused]] const std::string& digest_algorithm,
    const std::string& payload_digest,
    int ,
    const std::string& signature_b64,
    const std::string& session_handle,
    const std::optional<std::string>& user_label,
    const std::optional<std::string>& app_context) {
    // Generate a UUID for the signature ID
    std::string id = vhsm::utils::uuid_v4();

    // Column order matches sql_create_signature_records(); the legacy
    // digest_algorithm parameter is not stored (no dedicated column).
    std::vector<std::string> column_values;
    column_values.reserve(18);

    column_values.push_back(id);                 // id
    column_values.push_back(std::to_string(created_at));          // created_at
    column_values.push_back(std::to_string(slot_id));             // slot_id
    column_values.push_back(token_label);        // token_label
    column_values.push_back(key_id);             // key_id
    column_values.push_back(key_fingerprint);    // key_fingerprint
    column_values.push_back(mechanism);          // mechanism
    column_values.push_back(payload_digest);     // payload_digest
    column_values.push_back(signature_b64);      // signature_b64
    column_values.push_back(session_handle);     // session_handle
    column_values.push_back(user_label.value_or(""));   // user_label
    column_values.push_back(app_context.value_or("")); // app_context
    column_values.push_back("");                 // ledger_tx_id (NULL)
    column_values.push_back("0");                // ledger_block_num (NULL)
    column_values.push_back("");                 // ledger_tx_time
    column_values.push_back("");                 // ledger_tx_proof
    column_values.push_back("");                 // ledger_tx_set_b64
    column_values.push_back("PENDING");          // ledger_status

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
    } catch (const DbError& e) {
        // Log the error
        return std::nullopt;
    }

    return id;
}

bool SignatureRepository::update_ledger_fields(const std::string& signature_id,
                                               const vhsm::ledger::LedgerEntry& entry) {
    // Load the current row so we can preserve the non-ledger columns and any
    // previously captured ledger_tx_time / ledger_tx_proof / ledger_tx_set_b64.
    auto current_row = get_by_id(signature_id);
    if (!current_row) {
        return false;
    }

    // Row layout (matches sql_create_signature_records()):
    // 0: id | 1: created_at | 2: slot_id | 3: token_label | 4: key_id
    // 5: key_fingerprint | 6: mechanism | 7: payload_digest | 8: signature_b64
    // 9: session_handle | 10: user_label | 11: app_context
    // 12: ledger_tx_id | 13: ledger_block_num | 14: ledger_tx_time
    // 15: ledger_tx_proof | 16: ledger_tx_set_b64 | 17: ledger_status
    const auto& row = *current_row;
    if (row.size() < 18) {
        return false;
    }

    auto to_storage_string = [](const std::optional<std::string>& opt) -> std::string {
        return opt ? *opt : "";
    };

    std::vector<std::string> cols;
    cols.reserve(18);
    for (std::size_t i = 0; i < 12; ++i) {
        cols.push_back(to_storage_string(row[i]));
    }
    cols.push_back(entry.tx_id);              // 12: ledger_tx_id
    cols.push_back(std::to_string(entry.block_number)); // 13: ledger_block_num
    cols.push_back(to_storage_string(row[14])); // 14: ledger_tx_time (preserve)
    cols.push_back(to_storage_string(row[15])); // 15: ledger_tx_proof (preserve)
    cols.push_back(to_storage_string(row[16])); // 16: ledger_tx_set_b64 (preserve)
    cols.push_back("COMMITTED");              // 17: ledger_status

    const std::string sql = R"SQL(
        UPDATE signature_records SET
            id = ?,
            created_at = ?,
            slot_id = ?,
            token_label = ?,
            key_id = ?,
            key_fingerprint = ?,
            mechanism = ?,
            payload_digest = ?,
            signature_b64 = ?,
            session_handle = ?,
            user_label = ?,
            app_context = ?,
            ledger_tx_id = ?,
            ledger_block_num = ?,
            ledger_tx_time = ?,
            ledger_tx_proof = ?,
            ledger_tx_set_b64 = ?,
            ledger_status = ?
        WHERE id = ?;
    )SQL";

    std::vector<std::string> bind_params = cols;
    bind_params.push_back(signature_id);  // WHERE id

    try {
        conn_.exec(sql, bind_params);
    } catch (const DbError& e) {
        return false;
    }

    return true;
}

std::optional<std::vector<std::optional<std::string>>> SignatureRepository::get_by_id(const std::string& signature_id) const {
    const std::string sql = R"SQL(
        SELECT id, created_at, slot_id, token_label, key_id, key_fingerprint,
               mechanism, payload_digest, signature_b64, session_handle,
               user_label, app_context,
               ledger_tx_id, ledger_block_num, ledger_tx_time, ledger_tx_proof,
               ledger_tx_set_b64, ledger_status
        FROM signature_records
        WHERE id = ?;
    )SQL";

    try {
        auto rs = conn_.query(sql, {signature_id});
        if (rs.rows_.empty()) {
            return std::nullopt;
        }
        // We expect exactly one row.
        const DbRow& row = rs.rows_[0];
        std::vector<std::optional<std::string>> result;
        result.reserve(17);
        for (size_t i = 0; i < row.column_count(); ++i) {
            auto opt = row.get_string(i);
            if (opt) {
                // For the ledger_block_num column (index 13), we need to check if the string is "0" to mean NULL.
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
                // This should not happen because get_string returns nullopt only on conversion error?
                // But we treat it as NULL.
                result.push_back(std::nullopt);
            }
        }
        return result;
    } catch (const DbError& e) {
        return std::nullopt;
    }
}

}  // namespace db
}  // namespace vhsm::signature_store