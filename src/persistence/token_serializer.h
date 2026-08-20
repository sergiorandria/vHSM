#ifndef VHSM_PERSISTENCE_TOKEN_SERIALIZER_H
#define VHSM_PERSISTENCE_TOKEN_SERIALIZER_H

#include <cstdint>
#include <string>
#include <vector>

#include "../core/types.h"
#include "../keystore/token.h"

// WHY a TokenSerializer: PLAN.md Phase 7 requires persisting token state (the
// KEK, PIN flags, lockout counters) so a Backup/Restore flow can rebuild a
// Token after process restart.  The serializer converts a Token into a
// length-prefixed, versioned byte payload that the Vault encrypts at rest.
//
// Format note: PLAN.md listed protobuf for this component. We deliberately use
// a small self-describing binary encoding instead: it keeps `vhsm_persistence`
// free of a protobuf/protoc build dependency, works identically across
// platforms, and is trivially auditable (every field is (len,bytes) prefixed).
// The format is versioned so a future switch to protobuf can add a new version
// without breaking existing vaults (see migrations.h).
namespace vhsm::persistence {

struct TokenSnapshot {
    std::string label;
    std::string id;
    CK_ULONG    max_session_count;
    CK_ULONG    session_count;
    CK_ULONG    max_rw_session_count;
    CK_ULONG    rw_session_count;
    CK_BBOOL    token_initialized;
    CK_BBOOL    user_pin_set;
    CK_BBOOL    so_pin_set;
    CK_BBOOL    user_login_required;
    CK_BBOOL    so_login_required;
    unsigned    max_failed_attempts;
    unsigned    user_failed_attempts;
    unsigned    so_failed_attempts;
    CK_BBOOL    user_pin_locked;
    CK_BBOOL    so_pin_locked;
    std::vector<u8> kek;      // raw KEK (get_kek()); serialized as-is
};

// Serializes a TokenSnapshot into the versioned byte layout.
// Throws std::runtime_error on invalid input.
std::vector<u8> serialize_token_snapshot(const TokenSnapshot& snap);

// Deserializes bytes produced by serialize_token_snapshot().
// Throws std::runtime_error on malformed input or unknown version.
TokenSnapshot deserialize_token_snapshot(const std::vector<u8>& data);

// Convenience: builds a snapshot from a live Token. Only properties the public
// facade exposes are captured (identity, flags, counters, KEK).
TokenSnapshot snapshot_from_token(const vhsm::keystore::Token& token);

} // namespace vhsm::persistence

#endif // VHSM_PERSISTENCE_TOKEN_SERIALIZER_H