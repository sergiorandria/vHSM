#ifndef VHSM_CRYPTO_AES_GCM
#define VHSM_CRYPTO_AES_GCM

/*
 * aes_gcm.h
 *
 * Simple AES-256-GCM encryption/decryption helpers that encapsulate the
 * nonce, tag and ciphertext in `AESGCMResult` for easy transport.
 *
 * WHY AES-256-GCM (Galois/Counter Mode): GCM combines encryption (CTR mode)
 * with authentication (GHASH). This prevents tampering: if an attacker modifies
 * the ciphertext, decryption throws (tag verification fails). Unlike ECB or CBC
 * (which only encrypt), GCM ensures both confidentiality and authenticity with
 * a single operation. Standard for protecting data at rest and in transit.
 *
 * WHY bundle nonce+tag+ciphertext in AESGCMResult: GCM requires the same nonce
 * for encrypt and decrypt. The nonce must be stored alongside the ciphertext
 * (usually in plaintext; it's not secret). The 16-byte tag is appended to
 * ciphertext by GCM, but AESGCMResult separates them for clarity. Bundling all
 * three prevents the caller from losing one, which would make decryption fail.
 *
 * Usage notes:
 * - `encrypt` generates a 12-byte nonce and a 16-byte tag and returns the
 *   ciphertext along with the nonce and tag in `AESGCMResult`.
 * - `decrypt` verifies the GCM tag and returns the plaintext. On
 *   authentication failure it throws a runtime_error (fail-closed).
 *
 * Keys are expected to be 32 bytes for AES-256-GCM.
 */

#include <cstdint>
#include <vector>

#include "../domain/core/kernel_types.h"
#include "../domain/crypto/crypto_types.h"

namespace vhsm::crypto {
// WHY separate struct: Bundling the three components (ciphertext, nonce, tag)
// prevents them from being accidentally mismatched during transport. A caller
// can't accidentally use the tag from one operation with the ciphertext from
// another.
struct AESGCMResult {
  std::vector<u8> ciphertext;
  std::vector<u8> nonce;
  std::vector<u8> tag;
};

class AESGCM {
public:
  // WHY static methods: No state is needed. Encrypt/decrypt are pure
  // cryptographic operations. Static methods signal "these are utilities, not
  // objects that hold state". Thread-safe: each call uses separate OpenSSL
  // contexts.
  static AESGCMResult encrypt(const std::vector<u8> &key,
                              const std::vector<u8> &plaintext);

  // WHY decrypt returns std::vector (not optional): On success, it returns the
  // plaintext. On failure (tag mismatch), it throws runtime_error. This is
  // fail-closed: no return of invalid/corrupted plaintext. The caller either
  // gets valid data or an exception.
  static std::vector<u8> decrypt(const std::vector<u8> &key,
                                 const AESGCMResult &data);
};
} // namespace vhsm::crypto

#endif // VHSM_CRYPTO_AES_GCM