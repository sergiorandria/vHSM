#ifndef VHSM_SIGSTORE_SIGNATURE_REPOSITORY_H
#define VHSM_SIGSTORE_SIGNATURE_REPOSITORY_H

#include <optional>
#include <string>
#include <vector>

#include "../domain/core/kernel_types.h"
#include "../domain/crypto/crypto_types.h"
#include "../domain/signing/signature_record.h"
#include "../keystore/token.h"
#include "../ledger/ledger_entry.h"
#include "db_connection.h"

namespace vhsm::signature_store {
namespace db {

// WHY SignatureRepository is a data access layer: Abstracts database operations
// (insert, update, query) from business logic. This allows swapping databases
// (SQLite → PostgreSQL) without changing the dispatcher. The repository owns
// schema knowledge; callers don't know SQL.
//
// WHY insert returns optional<string> (signature_id or nullopt): Success case
// returns the generated ID (for later lookups/audits). Failure case returns
// nullopt (cleaner than exceptions for database constraints, which are common).
// The caller decides: if nullopt, log and notify.
//
// WHY update_ledger_fields updates only ledger-related fields: Signatures are
// immutable after creation (cannot change mechanism, key, signature bytes).
// Only ledger status can change (from PENDING → COMMITTED). Separating insert
// and update_ledger_fields enforces this constraint.
//
// WHY get_by_id returns vector<optional<string>>: Each column is an
// optional<string> because database values can be NULL (nullable columns).
// Wrapping in a vector represents the row. The caller (dispatcher) maps these
// to typed fields. This abstraction prevents tight coupling to database schema
// (easier to add columns without changing callers).

class SignatureRepository {
public:
  // WHY constructor takes IDbConnection& and Token&: Both required for
  // operations.
  // - conn: database connection (for queries)
  // - token: token reference (to access KEK for wrapping, if needed)
  SignatureRepository(IDbConnection &conn, vhsm::keystore::Token &token);

  // WHY insert: Persist a new signature record. The record is immutable after
  // creation. Fields include the signature itself, the key used, the mechanism,
  // digest, and audit metadata (user_label, session_handle, app_context).
  // Returns the generated signature ID on success, or nullopt if the operation
  // fails (constraint violation, I/O error, etc.).
  //
  // WHY so many parameters: Every field of the signature record is explicit (no
  // hidden state). This makes the contract clear: what data must be provided to
  // create a record. Callers (SignatureDispatcher) gather these from the
  // signing operation and context.
  std::optional<std::string>
  insert(int64_t created_at, int slot_id, const std::string &token_label,
         const std::string &key_id, const std::string &key_fingerprint,
         const std::string &mechanism, const std::string &digest_algorithm,
         const std::string &payload_digest, int payload_size,
         const std::string &signature_b64, const std::string &session_handle,
         const std::optional<std::string> &user_label,
         const std::optional<std::string> &app_context);

  // WHY update_ledger_fields: After the ledger worker commits the signature to
  // the blockchain, the record's ledger_* fields must be updated (ledger_hash,
  // ledger_timestamp, ledger_status). This is a separate operation because it's
  // asynchronous; the record is created immediately, but ledger commitment may
  // take seconds/minutes. Separating insert and update allows reading
  // "signatures pending ledger commit" (status='PENDING').
  //
  // WHY takes LedgerEntry: Contains all ledger metadata (hash, timestamp, block
  // ID, etc.). The repository persists these fields as-is (no transformation).
  bool update_ledger_fields(const std::string &signature_id,
                            const vhsm::ledger::LedgerEntry &entry);

  // WHY get_by_id: Retrieve a complete signature record for
  // auditing/verification. Returns a vector of optional strings (each column
  // value). Nulls are represented as optional.nullopt (no value). The caller
  // (dispatcher, audit) maps these to typed fields.
  std::optional<std::vector<std::optional<std::string>>>
  get_by_id(const std::string &signature_id) const;

private:
  IDbConnection &conn_;
  vhsm::keystore::Token &token_;
};

} // namespace db
} // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_SIGNATURE_REPOSITORY_H
