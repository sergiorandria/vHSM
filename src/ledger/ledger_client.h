#ifndef VHSM_LEDGER_LEDGER_CLIENT_H
#define VHSM_LEDGER_LEDGER_CLIENT_H

#include <string>
#include <optional>
#include "ledger_entry.h"

namespace vhsm::ledger {

class LedgerClient {
public:
    // Submits RecordSignature; blocks until endorsed + committed, or times out.
    // For Phase 4, we'll return nullopt (not implemented yet)
    std::optional<LedgerEntry> submit_record(const std::string& /*record_id*/,
                                           const std::string& /*key_fingerprint*/,
                                           const std::string& /*payload_digest*/,
                                           const std::string& /*signature_b64*/,
                                           int64_t /*created_at*/) {
        return std::nullopt;
    }

    // Queries GetRecord by record_id for verification.
    // For Phase 4, we'll return nullopt (not implemented yet)
    std::optional<LedgerEntry> get_record(const std::string& /*record_id*/) {
        return std::nullopt;
    }
};

}  // namespace vhsm::ledger

#endif // VHSM_LEDGER_LEDGER_CLIENT_H