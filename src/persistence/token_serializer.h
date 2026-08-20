#ifndef VHSM_PERSISTENCE_TOKEN_SERIALIZER_H
#define VHSM_PERSISTENCE_TOKEN_SERIALIZER_H

#include <cstdint>
#include <string>
#include <vector>

#include "../core/types.h"
#include "../keystore/token.h"

namespace vhsm::persistence {

class Vault; // defined in vault.h; forward-declared to avoid a heavy include

struct TokenSnapshot {
  std::string label;
  std::string id;
  CK_ULONG max_session_count;
  CK_ULONG session_count;
  CK_ULONG max_rw_session_count;
  CK_ULONG rw_session_count;
  CK_BBOOL token_initialized;
  CK_BBOOL user_pin_set;
  CK_BBOOL so_pin_set;
  CK_BBOOL user_login_required;
  CK_BBOOL so_login_required;
  unsigned max_failed_attempts;
  unsigned user_failed_attempts;
  unsigned so_failed_attempts;
  CK_BBOOL user_pin_locked;
  CK_BBOOL so_pin_locked;
  std::vector<u8> kek; // raw KEK (get_kek()); serialized as-is
};

// Serializes a TokenSnapshot into the versioned byte layout.
// Throws std::runtime_error on invalid input.
std::vector<u8> serialize_token_snapshot(const TokenSnapshot &snap);

// Deserializes bytes produced by serialize_token_snapshot().
// Throws std::runtime_error on malformed input or unknown version.
TokenSnapshot deserialize_token_snapshot(const std::vector<u8> &data);

// Convenience: builds a snapshot from a live Token. Only properties the public
// facade exposes are captured (identity, flags, counters, KEK).
TokenSnapshot snapshot_from_token(const vhsm::keystore::Token &token);

// Restores the durable state captured in a snapshot back into a live Token.
// This is the inverse of snapshot_from_token(): the caller opens/creates a
// vault (persistence::Vault), deserializes its payload, and feeds the fields
// back. Session counters are runtime state and are NOT restored (the caller
// re-accounts them via the session API).  Throws std::runtime_error on bad
// input.
void restore_token_from_snapshot(vhsm::keystore::Token &token,
                                 const TokenSnapshot &snap);

// Saves a live Token's snapshot into an existing (open) vault.  Thin helper so
// callers (C_Initialize/BackupToken) do not have to call the serializer + vault
// in the right order themselves.
void persist_token_to_vault(const vhsm::keystore::Token &token, Vault &vault);

// Loads a token snapshot from an open vault and restores it into the token.
// Throws std::runtime_error if the vault payload is not a valid snapshot.
void restore_token_from_vault(vhsm::keystore::Token &token, const Vault &vault);

} // namespace vhsm::persistence

#endif // VHSM_PERSISTENCE_TOKEN_SERIALIZER_H