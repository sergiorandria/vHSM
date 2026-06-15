#ifndef VHSM_SIGSTORE_SIGNATURE_REPOSITORY_H
#define VHSM_SIGSTORE_SIGNATURE_REPOSITORY_H

#define VHSM_REKOR_MODULE
#define REKOR_MODULE_VERSION 2

#include <string>
#include <optional>
#include <vector>

#include "../core/types.h"
#include "db_connection.h"
#include "row_integrity.h"
#include "../keystore/token.h"

#ifdef VHSM_REKOR_MODULE
#define VHSM_REKOR_ENABLED

#include "../rekor/rekor_client.h"

#endif // VHSM_REKOR_MODULE

namespace vhsm::signature_store {
namespace db {

class SignatureRepository {
public:
    SignatureRepository(IDbConnection& conn, vhsm::keystore::Token& token);

    // Insert a new signature record.
    // Returns the generated signature ID on success, or nullopt on failure.
    std::optional<std::string> insert(
        int64_t created_at,
        int slot_id,
        const std::string& token_label,
        const std::string& key_id,
        const std::string& key_fingerprint,
        const std::string& mechanism,
        const std::string& digest_algorithm,
        const std::string& payload_digest,
        int payload_size,
        const std::string& signature_b64,
        const std::string& session_handle,
        const std::optional<std::string>& user_label,
        const std::optional<std::string>& app_context);

    // Update the Rekor fields for a given signature record and recompute the integrity HMAC.
    // Returns true on success.
    bool update_rekor_fields(const std::string& signature_id,
                             const vhsm::rekor::RekorEntry& entry);

    // Retrieve a signature record by its ID.
    // Returns nullopt if not found.
    std::optional<std::vector<std::optional<std::string>>> get_by_id(const std::string& signature_id) const;

private:
    IDbConnection& conn_;
    vhsm::keystore::Token& token_;
    RowIntegrity row_integrity_;
};

}  // namespace db
}  // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_SIGNATURE_REPOSITORY_H