#include "verification_service.h"
#include "../ledger/ledger_client.h"

#include "../core/error.h"

#include <optional>

namespace vhsm::signature_store {
namespace db {

VerificationService::VerificationService(IDbConnection& conn, vhsm::ledger::LedgerClient& ledger_client,
                                         SignatureRepository& signature_repository)
    : conn_(conn), ledger_client_(ledger_client), signature_repository_(signature_repository) {}

VerificationService::VerificationResult VerificationService::verify_signature(const std::string& signature_id,
                                                                              bool check_ledger) const {
    VerificationResult result;
    result.local_record_exists = false;
    result.ledger_record_exists = false;
    result.payload_digest_match = false;
    result.signature_b64_match = false;
    result.key_fingerprint_match = false;

    // First, get the record from local DB
    auto local_row_opt = signature_repository_.get_by_id(signature_id);
    if (!local_row_opt) {
        result.error_detail = "Signature record not found in local DB";
        return result;
    }
    result.local_record_exists = true;

    // Extract fields from local row (vector of 17 optional<string>)
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

    const auto& local_row = local_row_opt.value();

    auto get_string_safe = [](const std::optional<std::string>& opt) -> std::string {
        return opt ? *opt : "";
    };

    auto get_int_safe = [](const std::optional<std::string>& opt) -> std::optional<int64_t> {
        if (!opt) return std::nullopt;
        if (opt->empty()) return std::nullopt;
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
    std::optional<int64_t> local_ledger_block_num_opt = get_int_safe(local_row[13]);

    // If we don't need to check ledger, just return that local record exists
    if (!check_ledger) {
        return result;
    }

    // If we have a ledger tx ID, try to get the record from ledger
    if (local_ledger_tx_id_opt) {
        auto ledger_entry_opt = ledger_client_.get_record(*local_ledger_tx_id_opt);
        if (ledger_entry_opt) {
            result.ledger_record_exists = true;
            result.ledger_tx_id = local_ledger_tx_id_opt;
            result.ledger_block_num = local_ledger_block_num_opt;

            // Compare fields
            result.payload_digest_match = (ledger_entry_opt->payload_digest == local_payload_digest);
            result.signature_b64_match = (ledger_entry_opt->signature_b64 == local_signature_b64);
            result.key_fingerprint_match = (ledger_entry_opt->key_fingerprint == local_key_fingerprint);
        } else {
            result.error_detail = "Ledger record not found for transaction ID";
        }
    } else {
        result.error_detail = "No ledger transaction ID in local record";
    }

    return result;
}

}  // namespace db
}  // namespace vhsm::signature_store