#include "ledger_retry_queue.h"
#include "../ledger/ledger_entry.h"

#include "../core/error.h"

#include <vector>

namespace vhsm::signature_store {
namespace db {

LedgerRetryQueue::LedgerRetryQueue(IDbConnection& conn) : conn_(conn) {}

std::vector<std::string> LedgerRetryQueue::scan_pending_rows() {
    std::vector<std::string> pending_ids;

    const std::string sql = R"SQL(
        SELECT id FROM signature_records
        WHERE ledger_status = 'PENDING';
    )SQL";

    try {
        auto rs = conn_.query(sql);
        for (const auto& row : rs.rows_) {
            auto id_opt = row.get_string(0);
            if (id_opt) {
                pending_ids.push_back(*id_opt);
            }
        }
    } catch (const DbError& e) {
        // In a real implementation, we might want to log this
        // For now, return empty vector on error
    }

    return pending_ids;
}

bool LedgerRetryQueue::update_ledger_status(const std::string& signature_id, const std::string& status) {
    const std::string sql = R"SQL(
        UPDATE signature_records
        SET ledger_status = ?
        WHERE id = ?;
    )SQL";

    try {
        conn_.exec(sql, {status, signature_id});
        return true;
    } catch (const DbError& e) {
        return false;
    }
}

bool LedgerRetryQueue::update_ledger_fields(const std::string& signature_id, const ledger::LedgerEntry& entry) {
    // First, retrieve the current row to get the non-ledger columns.
    auto current_row_opt = get_signature_row_by_id(signature_id);
    if (!current_row_opt) {
        return false;
    }

    // current_row is a vector of 17 optional<string> (in the order of the table columns).
    // We will replace the ledger columns (indices 12 to 16) with the new values.
    // Index mapping:
    // 0: id
    // 1: created_at
    // 2: slot_id
    // 3: token_label
    // 4: key_id
    // 5: key_fingerprint
    // 6: mechanism
    // 7: payload_digest
    // 8: signature_b64
    // 9: session_handle
    // 10: user_label
    // 11: app_context
    // 12: ledger_tx_id
    // 13: ledger_block_num
    // 14: ledger_tx_time
    // 15: ledger_tx_proof
    // 16: ledger_tx_set_b64
    // 17: ledger_status

    // We'll build a new vector of strings for the 17 columns (we don't have integrity_hmac anymore).
    std::vector<std::string> new_column_values;
    new_column_values.reserve(17);

    // Helper to convert optional<string> to string for storage: nullopt -> empty string, value -> value.
    auto to_storage_string = [](const std::optional<std::string>& opt) -> std::string {
        return opt ? *opt : "";
    };

    // Copy the first 12 columns (id through app_context) from current_row.
    for (size_t i = 0; i < 12; ++i) {
        new_column_values.push_back(to_storage_string(current_row_opt.value()[i]));
    }

    // Now the ledger columns: we will set them from the entry.
    // ledger_tx_id
    new_column_values.push_back(to_storage_string(std::make_optional<std::string>(entry.tx_id)));
    // ledger_block_num
    new_column_values.push_back(std::to_string(entry.block_num));
    // ledger_tx_time
    new_column_values.push_back(to_storage_string(std::make_optional<std::string>(entry.tx_time)));
    // ledger_tx_proof
    new_column_values.push_back(to_storage_string(std::make_optional<std::string>(entry.tx_proof)));
    // ledger_tx_set_b64
    new_column_values.push_back(to_storage_string(std::make_optional<std::string>(entry.tx_set_b64)));

    // ledger_status: we assume it's COMMITTED when we have a LedgerEntry.
    new_column_values.push_back("COMMITTED");

    // Now we have all 17 columns as strings. We can do the UPDATE.
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

    // Note: we have to include the WHERE condition. We'll add the signature_id at the end.
    // But our new_column_values already has the id as the first element? Actually, we built new_column_values
    // starting with id. So we have 17 values, and we need to add the WHERE condition which is the id again.
    // We'll create a new vector for the bind parameters: the 17 columns plus the WHERE id.
    std::vector<std::string> bind_params = new_column_values;
    bind_params.push_back(new_column_values[0]); // id for WHERE clause

    try {
        conn_.exec(sql, bind_params);
        return true;
    } catch (const DbError& e) {
        return false;
    }
}

// Helper function to get a signature row by ID
std::optional<std::vector<std::optional<std::string>>> LedgerRetryQueue::get_signature_row_by_id(const std::string& signature_id) {
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