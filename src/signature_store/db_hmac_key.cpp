#include "db_hmac_key.h"

#include <vector>
#include <string>

#include "../persistence/kdf.h"

namespace vhsm::signature_store {
namespace db {

DbHmacKey::DbHmacKey(IDbConnection& conn, vhsm::keystore::Token& token)
    : conn_(conn)
    , token_(token) {}

std::vector<std::uint8_t> DbHmacKey::get_key() const {
    // PLAN.md Phase 7: "Derive DB HMAC key from vault KEK using HKDF."
    // The Vault's payload is the token's durable state, which includes the KEK
    // (recovered on load-on-init; see persistence::restore_token_from_vault).
    // Deriving the DB-integrity key from that KEK via HKDF-SHA256 (fixed
    // "vHSM-db-hmac" info) gives a stable per-token integrity key without
    // storing the HMAC key or the DB key wrapped in db_meta.
    const std::vector<std::uint8_t> kek = token_.get_kek();
    if (kek.empty()) {
        // No KEK yet available (token not yet restored/initialized): callers
        // must treat an empty result as "integrity key not available".
        return {};
    }
    return vhsm::persistence::derive_db_hmac_key(kek);
}

void DbHmacKey::store_key_wrapped(const std::vector<std::uint8_t>& /*key*/) const {
    // Retained for API compatibility.  The DB integrity key is no longer
    // persisted in db_meta: it is derived from the vault KEK on demand, so
    // there is nothing to store here.  Do nothing.
}

}  // namespace db
}  // namespace vhsm::signature_store