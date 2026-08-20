#include "ledger_retry_queue.h"

#include "../core/error.h"
#include "../core/types.h"

#include <algorithm>
#include <cstdint>

namespace vhsm::signature_store {
namespace db {

LedgerRetryQueue::LedgerRetryQueue(IDbConnection& conn) : conn_(conn) {}

std::vector<std::string> LedgerRetryQueue::scan_pending_ids() {
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
    } catch (const DbError&) {
        // No PENDING rows (or DB unreachable) → nothing to retry.
    }

    return pending_ids;
}

std::optional<SignatureRecord> LedgerRetryQueue::load_pending_record(const std::string& signature_id) {
    const std::string sql = R"SQL(
        SELECT id, created_at, slot_id, token_label, key_id, key_fingerprint,
               mechanism, payload_digest, signature_b64, session_handle,
               user_label, app_context, ledger_status
        FROM signature_records
        WHERE id = ?;
    )SQL";

    auto to_str = [](const std::optional<std::string>& v) -> std::string {
        return v.value_or("");
    };

    try {
        auto rs = conn_.query(sql, {signature_id});
        if (rs.rows_.empty()) {
            return std::nullopt;
        }
        const DbRow& row = rs.rows_[0];

        // Column order (matches the SELECT above):
        // 0 id | 1 created_at | 2 slot_id | 3 token_label | 4 key_id
        // 5 key_fingerprint | 6 mechanism | 7 payload_digest | 8 signature_b64
        // 9 session_handle | 10 user_label | 11 app_context | 12 ledger_status
        SignatureRecord rec;
        rec.record_id        = to_str(row.get_string(0));
        rec.created_at       = std::strtoll(to_str(row.get_string(1)).c_str(), nullptr, 10);
        rec.slot_id          = static_cast<int>(std::strtol(to_str(row.get_string(2)).c_str(), nullptr, 10));
        rec.token_label      = to_str(row.get_string(3));
        rec.key_id           = to_str(row.get_string(4));
        rec.key_fingerprint  = to_str(row.get_string(5));
        rec.mechanism        = to_str(row.get_string(6));
        rec.payload_digest   = to_str(row.get_string(7));
        rec.signature_b64    = to_str(row.get_string(8));
        rec.session_handle   = to_str(row.get_string(9));

        const std::string user_label = to_str(row.get_string(10));
        rec.user_label = user_label.empty() ? std::nullopt
                                            : std::optional<std::string>(user_label);
        const std::string app_context = to_str(row.get_string(11));
        rec.app_context = app_context.empty() ? std::nullopt
                                              : std::optional<std::string>(app_context);

        // digest_algorithm / payload_size are not persisted; the ledger only
        // needs the digest + signature bytes, so re-derive size from the b64.
        rec.digest_algorithm = "";
        rec.payload_size = static_cast<int>(rec.signature_b64.size());
        rec.ledger_status = to_str(row.get_string(12));
        if (rec.ledger_status.empty()) {
            rec.ledger_status = "PENDING";
        }
        return rec;
    } catch (const DbError&) {
        return std::nullopt;
    }
}

std::vector<SignatureRecord> LedgerRetryQueue::load_pending_records() {
    std::vector<SignatureRecord> records;
    for (const auto& id : scan_pending_ids()) {
        auto rec = load_pending_record(id);
        if (rec) {
            records.push_back(std::move(*rec));
        }
    }
    return records;
}

}  // namespace db
}  // namespace vhsm::signature_store