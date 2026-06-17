#ifndef VHSM_SIGSTORE_LEDGER_RETRY_QUEUE_H
#define VHSM_SIGSTORE_LEDGER_RETRY_QUEUE_H

#include <string>
#include <vector>
#include <optional>
#include "db_connection.h"
#include "../core/utils.h"  // For DbRow type

namespace vhsm::signature_store {
namespace db {

// Forward declaration of LedgerEntry from ledger module
namespace ledger {
    struct LedgerEntry;
}

class LedgerRetryQueue {
public:
    explicit LedgerRetryQueue(IDbConnection& conn);

    // Scan for PENDING rows and return them for retry processing.
    // Returns vector of signature IDs that have PENDING ledger status.
    std::vector<std::string> scan_pending_rows();

    // Update the ledger status for a given signature ID.
    // Returns true on success.
    bool update_ledger_status(const std::string& signature_id, const std::string& status);

    // Update the ledger fields for a given signature ID with data from ledger.
    // Returns true on success.
    bool update_ledger_fields(const std::string& signature_id, const ledger::LedgerEntry& entry);

private:
    IDbConnection& conn_;

    // Helper function to get a signature row by ID
    std::optional<std::vector<std::optional<std::string>>> get_signature_row_by_id(const std::string& signature_id);
};

}  // namespace db
}  // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_LEDGER_RETRY_QUEUE_H