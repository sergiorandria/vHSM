#ifndef VHSM_SIGSTORE_SIGNATURE_REPOSITORY_H
#define VHSM_SIGSTORE_SIGNATURE_REPOSITORY_H

#include <string>
#include <optional>
#include <vector>

#include "../core/types.h"
#include "db_connection.h"
#include "../keystore/token.h"
#include "../ledger/ledger_entry.h"

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

    // Update the ledger fields for a given signature record.
    // Returns true on success.
    bool update_ledger_fields(const std::string& signature_id, const vhsm::ledger::LedgerEntry& entry);

    // Retrieve a signature record by its ID.
    // Returns nullopt if not found.
    std::optional<std::vector<std::optional<std::string>>> get_by_id(const std::string& signature_id) const;

private:
    IDbConnection& conn_;
    vhsm::keystore::Token& token_;
};

}  // namespace db
}  // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_SIGNATURE_REPOSITORY_H