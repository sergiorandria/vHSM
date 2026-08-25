#include "key_fingerprint.h"
#include "../core/error.h"
#include "vhsm/scrypto/ec.h"
#include "vhsm/scrypto/hash.h"
#include "vhsm/scrypto/rsa.h"

#include <cstdint>
#include <vector>

namespace vhsm::keystore {
namespace {
vhsm::scrypto::Curve to_scrypto(vhsm::crypto::Curve c) {
  switch (c) {
  case vhsm::crypto::Curve::EccCurveType_P256:
    return vhsm::scrypto::Curve::P256;
  case vhsm::crypto::Curve::EccCurveType_P384:
    return vhsm::scrypto::Curve::P384;
  case vhsm::crypto::Curve::EccCurveType_P521:
    return vhsm::scrypto::Curve::P521;
  }
  return vhsm::scrypto::Curve::P256;
}
} // namespace

// Fingerprint = SHA-256 over a canonical byte serialization of the key.
// The scrypto handle address is stable for the lifetime of the key object and
// unique per generated key, so it serves as canonical identity in this
// OpenSSL-free build (no DER/SPKI encoder exists in the clone).
//
// from_SPKI hashes whatever bytes the caller provides — unchanged semantics.

KeyFingerprint::Fingerprint
KeyFingerprint::from_SPKI(const std::vector<uint8_t> &spki) {
  auto h = vhsm::scrypto::sha256(spki.data(), spki.size());
  Fingerprint fp{};
  std::copy(h.begin(), h.end(), fp.begin());
  return fp;
}

KeyFingerprint::Fingerprint
KeyFingerprint::from_public_key(const vhsm::crypto::ECCKeyPair &key) {
  VHSM_CHECK_MSG(key.key != nullptr, "KeyFingerprint: null EC key handle");
  // Content-derived: SHA-256 over the exported SubjectPublicKeyInfo DER.
  // Pointer-identity hashing was wrong — the same key reloaded from a vault
  // (or moved) would change address and thus fingerprint, breaking audit
  // cross-references; distinct keys at recycled addresses could collide.
  auto spki = vhsm::scrypto::ec_export_public_spki({key.key, to_scrypto(key.curve)});
  return from_SPKI(spki);
}

KeyFingerprint::Fingerprint
KeyFingerprint::from_public_key(const vhsm::crypto::RSAKeyPair &key) {
  VHSM_CHECK_MSG(key.key != nullptr, "KeyFingerprint: null RSA key handle");
  auto spki = vhsm::scrypto::rsa_export_public_spki({key.key, key.bits});
  return from_SPKI(spki);
}

} // namespace vhsm::keystore