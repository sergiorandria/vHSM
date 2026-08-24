#include "key_fingerprint.h"
#include "../core/error.h"
#include "vhsm/scrypto/hash.h"

#include <cstdint>
#include <vector>

namespace vhsm::keystore {

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

namespace {
// Canonical bytes for an opaque key handle: type tag + pointer identity.
template <typename T>
KeyFingerprint::Fingerprint fingerprint_of_handle(int type_tag, T key) {
  // Fold type + address into a stable byte string, then SHA-256 it.
  std::vector<uint8_t> material(sizeof(int) + sizeof(void *));
  auto write_be = [](std::vector<uint8_t> &out, size_t off, uint64_t v,
                     size_t n) {
    for (size_t i = 0; i < n; ++i)
      out[off + i] = static_cast<uint8_t>(v >> (8 * (n - 1 - i)));
  };
  write_be(material, 0, static_cast<uint64_t>(type_tag), sizeof(int));
  write_be(material, sizeof(int),
           reinterpret_cast<uintptr_t>(static_cast<void *>(key)),
           sizeof(void *));
  auto h = vhsm::scrypto::sha256(material.data(), material.size());
  KeyFingerprint::Fingerprint fp{};
  std::copy(h.begin(), h.end(), fp.begin());
  return fp;
}
} // namespace

KeyFingerprint::Fingerprint
KeyFingerprint::from_public_key(const vhsm::crypto::ECCKeyPair &key) {
  VHSM_CHECK_MSG(key.key != nullptr,
                 "KeyFingerprint: null EC key handle");
  constexpr int kTagEc = 408; // EVP_PKEY_EC equivalent
  return fingerprint_of_handle(kTagEc, key.key);
}

KeyFingerprint::Fingerprint
KeyFingerprint::from_public_key(const vhsm::crypto::RSAKeyPair &key) {
  VHSM_CHECK_MSG(key.key != nullptr,
                 "KeyFingerprint: null RSA key handle");
  constexpr int kTagRsa = 6; // EVP_PKEY_RSA equivalent
  return fingerprint_of_handle(kTagRsa, key.key);
}

} // namespace vhsm::keystore
