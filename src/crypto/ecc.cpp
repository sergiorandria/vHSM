/*
 * ecc.cpp — EC via vhsm::scrypto policy wrapper (no OpenSSL EVP here).
 */
#include "ecc.h"
#include "../core/error.h"
#include "vhsm/scrypto/ec.h"

namespace vhsm::crypto {
namespace {
vhsm::scrypto::Curve to_scrypto(Curve c) {
  switch (c) {
  case Curve::EccCurveType_P256:
    return vhsm::scrypto::Curve::P256;
  case Curve::EccCurveType_P384:
    return vhsm::scrypto::Curve::P384;
  case Curve::EccCurveType_P521:
    return vhsm::scrypto::Curve::P521;
  }
  return vhsm::scrypto::Curve::P256;
}
} // namespace

void ecc_free_key(ECCKeyPair &kp) noexcept {
  if (kp.key) {
    vhsm::scrypto::ec_free({kp.key, to_scrypto(kp.curve)});
    kp.key = nullptr;
  }
}

ECCKeyPair ECC::generate_key(Curve curve) {
  auto kp = vhsm::scrypto::ec_generate(to_scrypto(curve));
  return ECCKeyPair{kp.handle, curve};
}

std::vector<uint8_t> ECC::sign(const ECCKeyPair &key,
                               const std::vector<uint8_t> &data) {
  VHSM_CHECK_MSG(key.key != nullptr, "ECC::sign: key is null");
  return vhsm::scrypto::ec_sign({key.key, to_scrypto(key.curve)}, data);
}

bool ECC::verify(const ECCKeyPair &key, const std::vector<uint8_t> &data,
                 const std::vector<uint8_t> &signature) {
  VHSM_CHECK_MSG(key.key != nullptr, "ECC::verify: key is null");
  try {
    return vhsm::scrypto::ec_verify({key.key, to_scrypto(key.curve)}, data,
                                    signature);
  } catch (const std::exception &) {
    throw;
  }
}

std::vector<uint8_t>
ECC::derive_shared_secret(const ECCKeyPair &priv, const ECCKeyPair &peer) {
  VHSM_CHECK_MSG(priv.key != nullptr, "ECC::derive: private key is null");
  VHSM_CHECK_MSG(peer.key != nullptr, "ECC::derive: peer key is null");
  return vhsm::scrypto::ecdh_derive({priv.key, to_scrypto(priv.curve)},
                                    {peer.key, to_scrypto(peer.curve)});
}
} // namespace vhsm::crypto
