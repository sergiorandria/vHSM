#ifndef VHSM_SIGSTORE_SIGNATURE_QUERY_H
#define VHSM_SIGSTORE_SIGNATURE_QUERY_H

#include <string>
#include <optional>
#include <vector>

#include "../core/types.h"
#include "db_connection.h"
#include "signature_repository.h"

// Forward declaration of RekorEntry and VerificationResult from other modules.
namespace vhsm::rekor {
    struct RekorEntry;
} // namespace vhsm::rekor

namespace vhsm::signature_store {
namespace db {

class SignatureQuery {
public:
    explicit SignatureQuery(IDbConnection& conn, keystore::Token&);

    // Retrieve a signature record by its ID.
    // Returns nullopt if not found.
    std::optional<std::vector<std::optional<std::string>>> get_signature_by_id(const std::string& signature_id) const;

    // Verify a signature by ID: check local HMAC and optionally verify Rekor proof.
    // Returns a struct with verification results.
    struct VerificationResult {
        bool local_hmac_ok;          // HMAC verification passed
        bool rekor_proof_ok;         // Rekor inclusion proof verified (if Rekor data present)
        bool payload_digest_match;   // Rekor payload digest matches local payload digest
        std::optional<std::string> error_detail;
    };
    VerificationResult verify_signature(const std::string& signature_id) const;

    // Query signatures by key fingerprint.
    std::vector<std::string> get_signature_ids_by_key_fingerprint(const std::string& key_fingerprint) const;

    // Query signatures by time range.
    std::vector<std::string> get_signature_ids_by_time_range(int64_t start_time, int64_t end_time) const;

private:
    IDbConnection& conn_;
    SignatureRepository signature_repository_;
};

}  // namespace db
}  // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_SIGNATURE_QUERY_H