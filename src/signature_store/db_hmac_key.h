#ifndef VHSM_SIGSTORE_DB_HMAC_KEY_H
#define VHSM_SIGSTORE_DB_HMAC_KEY_H

#include <string>
#include <vector>

#include "../domain/core/kernel_types.h"
#include "../domain/crypto/crypto_types.h"
#include "../domain/signing/signature_record.h"
#include "../keystore/token.h"

namespace vhsm::signature_store {
namespace db {

class IDbConnection;

// Retrieves the HMAC key used for row integrity checks.
// Per PLAN.md Phase 7, the key is derived from the token/vault KEK via HKDF
// (vhsm::persistence::derive_db_hmac_key) — it is NOT stored in the database.
// The KEK itself lives in the token and is recovered from the encrypted vault
// on load-on-init.  If the KEK is unavailable (token not yet initialized), the
// key is reported as absent (empty vector).
class DbHmacKey {
public:
  DbHmacKey(IDbConnection &conn, vhsm::keystore::Token &token);

  // Returns the HMAC key as a byte vector.
  // If the key is not yet available, returns empty vector.
  std::vector<std::uint8_t> get_key() const;

  // Stores the HMAC key wrapped in the db_meta table.
  // This should be called once during initialization after the KEK is
  // available.
  void store_key_wrapped(const std::vector<std::uint8_t> &key) const;

private:
  IDbConnection &conn_;
  vhsm::keystore::Token &token_;
};

} // namespace db
} // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_DB_HMAC_KEY_H