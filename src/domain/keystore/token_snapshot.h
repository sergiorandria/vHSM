#ifndef VHSM_DOMAIN_KEYSTORE_TOKEN_SNAPSHOT_H
#define VHSM_DOMAIN_KEYSTORE_TOKEN_SNAPSHOT_H

#include "../core/kernel_types.h"
#include "../pkcs11/pkcs11_types.h"
#include <string>
#include <vector>

namespace vhsm::domain::keystore {

// TokenSnapshot — domain DTO (DDD value object).
// Represents the durable state of a Token that can be persisted via a Vault
// without requiring the Token aggregate itself. Infrastructure (persistence)
// serializes this DTO; application code maps Token ↔ DTO.

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
  std::vector<u8> kek;
};

} // namespace vhsm::domain::keystore

#endif // VHSM_DOMAIN_KEYSTORE_TOKEN_SNAPSHOT_H
