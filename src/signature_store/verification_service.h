#ifndef VHSM_SIGSTORE_VERIFICATION_SERVICE_H
#define VHSM_SIGSTORE_VERIFICATION_SERVICE_H

#include <string>
#include <optional>
#include "../core/types.h"
#include "../ledger/ledger_client.h"
#include "db_connection.h"
#include "signature_repository.h"

namespace vhsm::signature_store {
namespace db {

class VerificationService {
public:
    VerificationService(IDbConnection& conn, vhsm::ledger::LedgerClient& ledger_client,
                        SignatureRepository& signature_repository);

    // Verify a signature by ID: check local DB and optionally verify with ledger.
    // Returns a struct with verification results.
    struct VerificationResult {
        bool local_record_exists;      // Record found in local DB
        bool ledger_record_exists;     // Record found in ledger (if checked)
        bool payload_digest_match;     // Ledger payload digest matches local payload digest
        bool signature_b64_match;      // Ledger signature matches local signature
        bool key_fingerprint_match;    // Ledger key fingerprint matches local key fingerprint
        std::optional<std::string> error_detail;
        std::optional<std::string> ledger_tx_id;
        std::optional<int64_t> ledger_block_num;
    };

    VerificationResult verify_signature(const std::string& signature_id,
                                        bool check_ledger = true) const;

private:
    IDbConnection& conn_;
    vhsm::ledger::LedgerClient& ledger_client_;
    SignatureRepository& signature_repository_;
};

}  // namespace db
}  // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_VERIFICATION_SERVICE_H