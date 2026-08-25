#ifndef VHSM_PERSISTENCE_VAULT_FORMAT_H
#define VHSM_PERSISTENCE_VAULT_FORMAT_H

#include <cstdint>

// WHY a well-defined on-disk format: The vault is the single recovery path for
// encrypted token state. The magic/version header lets us detect (a) files that
// are not vaults at all and (b) old layouts that need migrating (see
// migrations.h). Everything after the fixed header is length-prefixed, so the
// layout can grow without breaking forward compat when we add new sections.
namespace vhsm::persistence {

// Magic bytes at offset 0. Used to reject non-vault files before we even try
// to derive a KEK (avoids wasteful PBKDF2 runs on random data).
inline constexpr char K_VAULT_MAGIC[8] = {'V', 'H', 'S', 'M', 'V', 'A', 'U', 'L'};

// Version history:
//   1 — initial layout: header + PBKDF2 params + AES-256-GCM blob
inline constexpr std::uint32_t K_VAULT_FORMAT_VERSION = 1;

// PBKDF2 hardening parameter.  600k iterations matches the PIN-derivation
// budget used elsewhere in vHSM (PKCS#5 recommendation for 2023+).  Exposed as
// a constant so tests can lower it for speed while production keeps the real
// cost.
inline constexpr std::uint32_t K_VAULT_PBKDF2_ITERATIONS = 600'000;

// AES-256-GCM parameter sizes (see crypto/aes_gcm.h).
inline constexpr std::size_t K_VAULT_SALT_LEN = 16;  // PBKDF2 salt
inline constexpr std::size_t K_VAULT_NONCE_LEN = 12; // GCM IV
inline constexpr std::size_t K_VAULT_TAG_LEN = 16;   // GCM auth tag
inline constexpr std::size_t K_VAULT_KEY_LEN = 32;   // AES-256 key

// Fixed header layout (little-endian): all sizes below are in bytes.
//   0..7    magic
//   8..11   format version (u32)
//   12..27  PBKDF2 salt        (K_VAULT_SALT_LEN)
//   28..31  PBKDF2 iterations  (u32)
//   32..43  GCM nonce          (K_VAULT_NONCE_LEN)
//   44..59  GCM tag            (K_VAULT_TAG_LEN)
//   60..67  ciphertext length  (u64)
//   68..    ciphertext payload
inline constexpr std::size_t K_VAULT_HEADER_LEN =
    8 + 4 + K_VAULT_SALT_LEN + 4 + K_VAULT_NONCE_LEN + K_VAULT_TAG_LEN + 8;

} // namespace vhsm::persistence

#endif // VHSM_PERSISTENCE_VAULT_FORMAT_H