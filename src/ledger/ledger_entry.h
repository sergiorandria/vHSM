#ifndef VHSM_LEDGER_LEDGER_ENTRY_H
#define VHSM_LEDGER_LEDGER_ENTRY_H

#include <string>
#include <cstdint>

namespace vhsm::ledger {

struct LedgerEntry {
    std::string record_id;
    std::string key_fingerprint;
    std::string payload_digest;
    std::string signature_b64;
    int64_t      created_at;
    std::string  tx_id;        // Fabric transaction ID
    int64_t      block_number;  // block height at commitment
};

}  // namespace vhsm::ledger

#endif // VHSM_LEDGER_LEDGER_ENTRY_H