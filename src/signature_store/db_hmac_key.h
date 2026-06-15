#ifndef VHSM_SIGSTORE_DB_HMAC_KEY_H
#define VHSM_SIGSTORE_DB_HMAC_KEY_H

#include <string>
#include <vector>

#include "../core/types.h"

namespace vhsm::signature_store {
namespace db {

class IDbConnection;

// Retrieves the HMAC key used for row integrity checks.
// The key is derived from the KEK (key encryption key) via HKDF.
// For simplicity in this implementation, we return a fixed key.
// In production, this should be securely retrieved from the key store.
class DbHmacKey {
public:
    explicit DbHmacKey(IDbConnection& conn);

    // Returns the HMAC key as a byte vector.
    // If the key is not yet available, returns empty vector.
    std::vector<std::uint8_t> get_key() const;

    // Stores the HMAC key wrapped in the db_meta table.
    // This should be called once during initialization after the KEK is available.
    void store_key_wrapped(const std::vector<std::uint8_t>& key) const;

private:
    IDbConnection& conn_;
};

}  // namespace db
}  // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_DB_HMAC_KEY_H