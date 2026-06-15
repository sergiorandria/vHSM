#include "signature_repository.h"

#include "../core/error.h"
#include "../core/utils.h"

#include <chrono>
#include <sstream>
#include <vector>

namespace vhsm::signature_store {
namespace db {

SignatureRepository::SignatureRepository(IDbConnection& conn)
    : conn_(conn), row_integrity_(conn) {}

std::optional<std::string> SignatureRepository::insert(
    int64_t created_at,
    int slot_id,
    const std::string& token_label,
    const std::string& key_id,
    const std::string& key_fingerprint,
    const std::string& mechanism,
    const std::string& digest_algorithm,
    const std::string& payload_digest,
    int payload_size,
    const std::string& signature_b64,
    const std::string& session_handle,
    const std::optional<std::string>& user_label,
    const std::optional<std::string>& app_context) {
    // Generate a UUID for the signature ID
    std::string id = vhsm::utils::uuid_v4();

    // Prepare column values as strings for the first 17 columns (excluding integrity_hmac)
    // We use empty string for NULL text columns and "0" for NULL integer column.
    std::vector<std::string> column_values;
    column_values.reserve(17);

    column_values.push_back(id); // id
    column_values.push_back(std::to_string(created_at)); // created_at
    column_values.push_back(std::to_string(slot_id)); // slot_id
    column_values.push_back(token_label); // token_label
    column_values.push_back(key_id); // key_id
    column_values.push_back(key_fingerprint); // key_fingerprint
    column_values.push_back(mechanism); // mechanism
    column_values.push_back(digest_algorithm); // digest_algorithm
    column_values.push_back(payload_digest); // payload_digest
    column_values.push_back(signature_b64); // signature_b64
    column_values.push_back(session_handle); // session_handle
    column_values.push_back(user_label.value_or("")); // user_label: empty string if nullopt
    column_values.push_back(app_context.value_or("")); // app_context: empty string if nullopt
    column_values.push_back(""); // rekor_entry_uuid: NULL -> empty string
    column_values.push_back("0"); // rekor_log_index: NULL -> "0"
    column_values.push_back(""); // rekor_integrated_time: NULL -> empty string
    column_values.push_back(""); // rekor_inclusion_proof: NULL -> empty string
    column_values.push_back(""); // rekor_set_b64: NULL -> empty string
    column_values.push_back("PENDING"); // rekor_status

    // Compute the integrity HMAC over these column values (as optional<string>)
    // We need to convert our string vector to vector<optional<string>> for the HMAC function.
    // Empty string represents NULL, so we convert empty string to nullopt, non-empty to the string.
    std::vector<std::optional<std::string>> hmac_inputs;
    hmac_inputs.reserve(column_values.size());
    for (const auto& val : column_values) {
        if (val.empty()) {
            hmac_inputs.push_back(std::nullopt);
        } else {
            hmac_inputs.push_back(val);
        }
    }
    std::string integrity_hmac = row_integrity_.compute_hmac(hmac_inputs);
    if (integrity_hmac.empty()) {
        // Unable to compute HMAC
        return std::nullopt;
    }

    // Now we have the integrity_hmac, add it as the 18th column
    column_values.push_back(integrity_hmac);

    // Now insert the row
    const std::string sql = R"SQL(
        INSERT INTO signature_records (
            id, created_at, slot_id, token_label, key_id, key_fingerprint,
            mechanism, payload_digest, signature_b64, session_handle,
            user_label, app_context, rekor_entry_uuid, rekor_log_index,
            rekor_integrated_time, rekor_inclusion_proof, rekor_set_b64,
            rekor_status, integrity_hmac
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
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

bool SignatureRepository::update_rekor_fields(const std::string& signature_id,
                                              const vhsm::rekor::RekorEntry& entry) {
    // Prepare the column values for the Rekor columns and the integrity_hmac.
    // We will update the rekor_* columns and then recompute the integrity_hmac over the entire row
    // (excluding the integrity_hmac column itself).

    // First, retrieve the current row to get the non-Rekor columns.
    auto current_row = get_by_id(signature_id);
    if (!current_row) {
        return false;
    }

    // current_row is a vector of 18 optional<string> (in the order of the table columns).
    // We will replace the Rekor columns (indices 12 to 16) with the new values.
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
    // 12: rekor_entry_uuid
    // 13: rekor_log_index
    // 14: rekor_integrated_time
    // 15: rekor_inclusion_proof
    // 16: rekor_set_b64
    // 17: rekor_status
    // 18: integrity_hmac

    // We'll build a new vector of strings for the 18 columns (including integrity_hmac) for the UPDATE.
    // We'll compute the integrity_hmac based on the first 17 columns (with the new Rekor values).

    std::vector<std::string> new_column_values;
    new_column_values.reserve(18);

    // Helper to convert optional<string> to string for storage: nullopt -> empty string, value -> value.
    auto to_storage_string = [](const std::optional<std::string>& opt) -> std::string {
        return opt ? *opt : "";
    };

    // Copy the first 11 columns (id through app_context) from current_row.
    for (size_t i = 0; i < 11; ++i) {
        new_column_values.push_back(to_storage_string(current_row.value()[i]));
    }

    // Now the Rekor columns: we will set them from the entry.
    // rekor_entry_uuid
    new_column_values.push_back(to_storage_string(std::make_optional<std::string>(entry.entry_uuid)));
    // rekor_log_index: if entry.log_index is 0, we treat it as NULL? But the RekorEntry log_index is int64_t.
    // We will store the log_index as a string, and if it is 0, we store "0" to mean NULL?
    // But note: we are using "0" as the sentinel for NULL in the integer column.
    // However, the RekorEntry log_index might be 0? We assume it's not.
    // We will store the log_index as a string, and if we want to store NULL we would store "0", but we don't have a NULL from the entry.
    // The RekorEntry always has a valid log_index and entry_uuid, etc.
    // So we store the actual log_index.
    new_column_values.push_back(std::to_string(entry.log_index));
    // rekor_integrated_time
    new_column_values.push_back(to_storage_string(std::make_optional<std::string>(entry.integrated_time)));
    // rekor_inclusion_proof
    new_column_values.push_back(to_storage_string(std::make_optional<std::string>(entry.inclusion_proof)));
    // rekor_set_b64
    new_column_values.push_back(to_storage_string(std::make_optional<std::string>(entry.set_b64)));

    // rekor_status: we assume it's COMMITTED when we have a RekorEntry.
    new_column_values.push_back("COMMITTED");

    // Now we have the first 17 columns (up to rekor_status) in new_column_values.
    // We need to compute the integrity_hmac over these 17 columns (as optional<string>).
    std::vector<std::optional<std::string>> hmac_inputs;
    hmac_inputs.reserve(new_column_values.size());
    for (const auto& val : new_column_values) {
        if (val.empty()) {
            hmac_inputs.push_back(std::nullopt);
        } else {
            hmac_inputs.push_back(val);
        }
    }
    std::string integrity_hmac = row_integrity_.compute_hmac(hmac_inputs);
    if (integrity_hmac.empty()) {
        return false;
    }
    new_column_values.push_back(integrity_hmac); // 18th column

    // Now we have all 18 columns as strings. We can do the UPDATE.
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
            rekor_entry_uuid = ?,
            rekor_log_index = ?,
            rekor_integrated_time = ?,
            rekor_inclusion_proof = ?,
            rekor_set_b64 = ?,
            rekor_status = ?,
            integrity_hmac = ?
        WHERE id = ?;
    )SQL";

    // Note: we have to include the WHERE condition. We'll add the signature_id at the end.
    // But our new_column_values already has the id as the first element? Actually, we built new_column_values
    // starting with id. So we have 18 values, and we need to add the WHERE condition which is the id again.
    // We'll create a new vector for the bind parameters: the 18 columns plus the WHERE id.
    std::vector<std::string> bind_params = new_column_values;
    bind_params.push_back(new_column_values[0]); // id for WHERE clause

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
               user_label, app_context, rekor_entry_uuid, rekor_log_index,
               rekor_integrated_time, rekor_inclusion_proof, rekor_set_b64,
               rekor_status, integrity_hmac
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
        result.reserve(18);
        for (size_t i = 0; i < row.column_count(); ++i) {
            auto opt = row.get_string(i);
            if (opt) {
                // For the rekor_log_index column (index 13), we need to check if the string is "0" to mean NULL.
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