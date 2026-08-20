#ifndef VHSM_KEYSTORE_KEY_FINGERPRINT
#define VHSM_KEYSTORE_KEY_FINGERPRINT

#include "../crypto/ecc.h"
#include "../crypto/rsa.h"

#include <array>

namespace vhsm::keystore {

// WHY KeyFingerprint static utility class: Key fingerprinting is a pure
// function (same key → same fingerprint). No state needed. Making it a static
// utility class (no instances) makes this clear and prevents accidental
// instantiation.
//
// WHY fingerprints from keys/SPKI: Different representations of the same key
// must produce the same fingerprint. We support:
// - from_SPKI: DER-encoded public key (standard wire format)
// - from_public_key: Already-decoded ECC/RSA key objects
// All paths hash the canonical public key material, ensuring consistency.
class KeyFingerprint {
public:
  // WHY 32-byte (256-bit) fingerprints: Strong enough to be collision-resistant
  // (2^-128 birthday bound). SHA-256 produces 256 bits; we use all of it.
  using Fingerprint = std::array<uint8_t, 32>;

  /**
   * @brief Compute a fingerprint from a DER-encoded SPKI public key.
   * @param spki Bytes of the SPKI (SubjectPublicKeyInfo) DER structure.
   * @return 32-byte SHA-256 fingerprint of the public key material.
   *
   * WHY from_SPKI takes raw bytes: SPKI is the standard ASN.1 encoding from
   * certificates and CSRs. Accepting raw DER avoids needing an ASN.1 parser at
   * this layer. The caller (certificate import) provides the bytes; we hash
   * them.
   */
  static Fingerprint from_SPKI(const std::vector<uint8_t> &spki);

  // WHY overloads for ECC and RSA: Different key types have different layouts.
  // Overloads let us extract the canonical public key bytes for each type, then
  // hash. This ensures keys imported as SPKI match keys imported as objects.
  static Fingerprint from_public_key(const vhsm::crypto::ECCKeyPair &key);
  static Fingerprint from_public_key(const vhsm::crypto::RSAKeyPair &key);
};
} // namespace vhsm::keystore
#endif // VHSM_KEYSTORE_KEY_FINGERPRINT