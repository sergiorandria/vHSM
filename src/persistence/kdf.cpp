#include "kdf.h"

#include <cstring>
#include <stdexcept>

#include "../core/error.h"
#include "../core/macros.h"
#include "vhsm/scrypto/hmac.h"
#include "vhsm/scrypto/kdf.h"

// PBKDF2 via vhsm::scrypto (RFC 2898). Salt and password are passed as raw
// bytes; the caller is responsible for not logging them.
std::vector<u8> vhsm::persistence::derive_vault_key(const std::string &password,
                                                    const std::vector<u8> &salt,
                                                    std::uint32_t iterations,
                                                    std::size_t out_len) {
  VHSM_CHECK_MSG(!password.empty(),
                 "derive_vault_key: password must not be empty");
  VHSM_CHECK_MSG(!salt.empty(), "derive_vault_key: salt must not be empty");
  VHSM_CHECK_MSG(iterations > 0, "derive_vault_key: iterations must be > 0");
  VHSM_CHECK_MSG(out_len > 0, "derive_vault_key: out_len must be > 0");

  return vhsm::scrypto::pbkdf2_hmac_sha256(password, salt, iterations, out_len);
}

// HKDF-SHA256 per RFC 5869 — delegated to vhsm::scrypto (Extract+Expand).
std::vector<u8> vhsm::persistence::hkdf_sha256(const std::vector<u8> &ikm,
                                               const std::vector<u8> &salt,
                                               const std::vector<u8> &info,
                                               std::size_t out_len) {
  VHSM_CHECK_MSG(!ikm.empty(), "hkdf_sha256: IKM must not be empty");
  VHSM_CHECK_MSG(out_len > 0, "hkdf_sha256: out_len must be > 0");

  return vhsm::scrypto::hkdf_sha256(ikm, salt, info, out_len);
}

// The DB HMAC key is derived from the vault KEK with a fixed info string so it
// is stable across process restarts (the vault KEK does not change).
std::vector<u8>
vhsm::persistence::derive_db_hmac_key(const std::vector<u8> &vault_kek) {
  return vhsm::scrypto::derive_db_hmac_key(vault_kek);
}

// End of translation unit.
