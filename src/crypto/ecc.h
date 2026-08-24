/*
 * ecc.h
 *
 * Elliptic Curve wrapper declarations backed by vhsm::scrypto (hardened
 * clone). NIST P-256/P-384/P-521 only. Key handle is opaque; free with
 * ecc_free_key().
 */
#pragma once

#include <cstdint>
#include <vector>

namespace vhsm::crypto {

enum class Curve {
  EccCurveType_P256, // NIST P-256 (secp256r1): 128-bit security
  EccCurveType_P384, // NIST P-384 (secp384r1): 192-bit security
  EccCurveType_P521  // NIST P-521 (secp521r1): 260-bit security
};

struct ECCKeyPair {
  void *key = nullptr;
  Curve curve = Curve::EccCurveType_P256;
};

void ecc_free_key(ECCKeyPair &kp) noexcept;

class ECC {
public:
  static ECCKeyPair generate_key(Curve curve);
  static std::vector<uint8_t> sign(const ECCKeyPair &key,
                                   const std::vector<uint8_t> &data);
  static bool verify(const ECCKeyPair &key, const std::vector<uint8_t> &data,
                     const std::vector<uint8_t> &signature);
  static std::vector<uint8_t> derive_shared_secret(const ECCKeyPair &priv,
                                                   const ECCKeyPair &peer);
};
} // namespace vhsm::crypto
