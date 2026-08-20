#ifndef VHSM_PERSISTENCE_KDF_H
#define VHSM_PERSISTENCE_KDF_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "../core/types.h"

// WHY KDF utilities live in persistence: PBKDF2 and HKDF are used to turn a
// human-entered password into the vault AES key and to derive the DB HMAC key
// from the vault KEK (PLAN.md Phase 7).  Keeping the primitives here (rather
// than crypto/) scopes them to storage-layer hardening; crypto/ stays focused
// on PKCS#11 operators.
namespace vhsm::persistence {

// Derives a key from a password using PBKDF2-HMAC-SHA256 (OpenSSL).
// `iterations` is deliberately configurable so tests can use low values.
// Throws std::runtime_error if the PRF call fails.
std::vector<u8> derive_vault_key(const std::string &password,
                                 const std::vector<u8> &salt,
                                 std::uint32_t iterations, std::size_t out_len);

// HKDF-SHA256 (RFC 5869): Extract-and-Expand.
// `salt` may be empty (then a zero-filled salt of hash length is used).
// Throws std::runtime_error on OpenSSL failure or invalid parameters.
std::vector<u8> hkdf_sha256(const std::vector<u8> &ikm,
                            const std::vector<u8> &salt,
                            const std::vector<u8> &info, std::size_t out_len);

// Convenience: 32-byte key derivation used as the DB HMAC key (see
// signature_store/db_hmac_key.h). One call site, so we keep it here instead of
// scattering HKDF options around the codebase.
std::vector<u8> derive_db_hmac_key(const std::vector<u8> &vault_kek);

} // namespace vhsm::persistence

#endif // VHSM_PERSISTENCE_KDF_H