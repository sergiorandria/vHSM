/*
 * crypto_engine.cpp
 *
 * CryptoEngine dispatches a signing request to the correct primitive based on
 * the key type. All primitives come from vhsm::scrypto (hardened clone).
 */

#include "crypto_engine.h"

#include "../core/error.h"
#include "../core/types.h"
#include "vhsm/scrypto/hash.h"

namespace vhsm::crypto {

namespace {

// SHA-256 of `data` returned as a lowercase hex string (matches the hex
// digest format persisted in SignatureRecord.payload_digest).
std::string sha256_hex(const std::vector<u8> &data) {
  auto raw = vhsm::scrypto::sha256(data.data(), data.size());
  static const char *kHex = "0123456789abcdef";
  std::string hex;
  hex.reserve(raw.size() * 2);
  for (unsigned char b : raw) {
    hex.push_back(kHex[b >> 4]);
    hex.push_back(kHex[b & 0x0F]);
  }
  return hex;
}

SignResult make_result(const std::vector<uint8_t> &signature,
                       const std::vector<u8> &data,
                       const char *mechanism) {
  SignResult result;
  result.payload_digest = sha256_hex(data);
  result.digest_alg = "SHA-256";
  result.payload_size = static_cast<int>(data.size());
  result.signature = signature;
  result.mechanism_str = mechanism;
  return result;
}

} // namespace

SignResult CryptoEngine::sign(const RSAKeyPair &key,
                              const std::vector<u8> &data,
                              const std::string &requested_mechanism) {
  VHSM_CHECK_MSG(key.key != nullptr, "CryptoEngine::sign: key is null");
  (void)requested_mechanism; // audit hint only; native algorithm is used
  return make_result(RSAUtil::sign(key, data), data, "CKM_SHA256_RSA_PKCS");
}

SignResult CryptoEngine::sign(const ECCKeyPair &key,
                              const std::vector<u8> &data,
                              const std::string &requested_mechanism) {
  VHSM_CHECK_MSG(key.key != nullptr, "CryptoEngine::sign: key is null");
  (void)requested_mechanism;
  return make_result(ECC::sign(key, data), data, "CKM_ECDSA_SHA256");
}

} // namespace vhsm::crypto
