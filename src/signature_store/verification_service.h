#ifndef VHSM_SIGSTORE_VERIFICATION_SERVICE_H
#define VHSM_SIGSTORE_VERIFICATION_SERVICE_H

#include <string>
#include <optional>
#include "../core/types.h"
#include "../ledger/ledger_client.h"
#include "db_connection.h"
#include "signature_repository.h"
#include "internal/verification_service_core.h"

namespace vhsm::signature_store {
namespace db {

// Public facade for signature verification.  Validates the caller-supplied
// signature_id and delegates the local-vs-ledger comparison to the internal
// core, which owns all verification logic.
class VerificationService {
public:
    VerificationService(IDbConnection& conn, vhsm::ledger::LedgerClient& ledger_client,
                        SignatureRepository& signature_repository);

    // Verify a signature by ID: check local DB and optionally verify with ledger.
    // Returns a struct with verification results.
    using VerificationResult = internal::v_VerificationResult_M1;

    VerificationResult verify_signature(const std::string& signature_id,
                                        bool check_ledger = true);

private:
    internal::v_VerificationServiceCore_M1 v_core_;
};

}  // namespace db
}  // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_VERIFICATION_SERVICE_H
