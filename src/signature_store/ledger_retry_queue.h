#ifndef VHSM_SIGSTORE_LEDGER_RETRY_QUEUE_H
#define VHSM_SIGSTORE_LEDGER_RETRY_QUEUE_H

#include <string>
#include <vector>
#include <optional>
#include "db_connection.h"
#include "../core/types.h"

namespace vhsm::signature_store {
namespace db {

// WHY LedgerRetryQueue is a thin recovery seam: the signature DB is the source
// of truth for "which records still need anchoring".  A record left with
// ledger_status='PENDING' after a crash / worker death must be re-submitted on
// the next start-up.  This class scans the DB for those rows and reconstructs
// the SignatureRecord objects the LedgerWorker expects (the raw DB columns and
// the wire record differ slightly — digest_algorithm / payload_size are not
// persisted, so they are re-derived).
//
// WHY separate from SignatureRepository: the repository owns generic
// create/read of signature rows; the retry queue owns the specific "find
// unanchored + resubmit" workflow.  Keeping them separate makes the crash
// recovery path explicit and independently testable.
class LedgerRetryQueue {
public:
    explicit LedgerRetryQueue(IDbConnection& conn);

    // Scan for ledger_status='PENDING' rows and return their signature IDs.
    std::vector<std::string> scan_pending_ids();

    // Reconstruct a full SignatureRecord for a row previously returned by
    // scan_pending_ids().  Returns std::nullopt if the row no longer exists
    // or cannot be reconstructed.
    std::optional<SignatureRecord> load_pending_record(const std::string& signature_id);

    // Convenience: scan + load every PENDING record as a ready-to-submit
    // SignatureRecord.  Missing/unparseable rows are skipped.
    std::vector<SignatureRecord> load_pending_records();

private:
    IDbConnection& conn_;
};

}  // namespace db
}  // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_LEDGER_RETRY_QUEUE_H