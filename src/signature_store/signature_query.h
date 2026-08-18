#ifndef VHSM_SIGSTORE_SIGNATURE_QUERY_H
#define VHSM_SIGSTORE_SIGNATURE_QUERY_H

#include <string>
#include <optional>
#include <vector>

#include "../core/types.h"
#include "db_connection.h"
#include "signature_repository.h"
#include "../ledger/ledger_client.h"
#include "internal/signature_query_core.h"

namespace vhsm::signature_store {
namespace db {

// Public facade for signature queries and verification.  Validates the
// caller-supplied identifiers / time range and delegates all SQL and
// ledger cross-check logic to the internal core.
class SignatureQuery {
public:
    explicit SignatureQuery(IDbConnection& conn, keystore::Token&);

    // Retrieve a signature record by its ID.
    // Returns nullopt if not found.
    std::optional<std::vector<std::optional<std::string>>> get_signature_by_id(const std::string& signature_id) const;

    // Verifies a signature by ID.
    //
    // Local-only form: reports whether the local record exists and what its
    // anchored Fabric ledger status is.  It cannot prove tamper-evidence on
    // its own — that requires the ledger cross-check (see the overload below).
    using VerificationResult = internal::v_SignatureQueryVerificationResult_M1;

    VerificationResult verify_signature(const std::string& signature_id) const;

    // Live form: additionally queries the Fabric ledger via `ledger` and
    // cross-checks payload_digest / signature_b64 / key_fingerprint.  This is
    // the tamper-evident form — it does not require trusting the local DB.
    VerificationResult verify_signature(const std::string& signature_id, vhsm::ledger::LedgerClient& ledger);

    // Query signatures by key fingerprint.
    std::vector<std::string> get_signature_ids_by_key_fingerprint(const std::string& key_fingerprint);

    // Query signatures by time range.
    std::vector<std::string> get_signature_ids_by_time_range(int64_t start_time, int64_t end_time);

private:
    internal::v_SignatureQueryCore_M1 v_core_;
};

}  // namespace db
}  // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_SIGNATURE_QUERY_H
