/*
 * crypto_engine.cpp
 *
 * CryptoEngine dispatches a signing request to the primitive matching the
 * key's algorithm family. All primitives come from vhsm::scrypto (hardened
 * clone). A requested mechanism that conflicts with the key family is
 * rejected with CKR_KEY_TYPE_INCONSISTENT unless the caller explicitly opts
 * into native fallback (MechanismPolicy::AllowNativeFallback) — silent
 * algorithm substitution produced signatures verifiers would reject.
 */

#include "crypto_engine.h"

#include "../core/error.h"
#include "../domain/core/kernel_types.h"
#include "../domain/crypto/crypto_types.h"
#include "vhsm/scrypto/hash.h"

namespace vhsm::crypto {

namespace {

// SHA-256 of `data` returned as a lowercase hex string (matches the hex
// digest format persisted in SignatureRecord.payload_digest).
std::string sha256_hex(const std::vector<u8> &data) {
  auto raw = vhsm::scrypto::sha256(data.data(), data.size());
  static constexpr char K_HEX[] = "0123456789abcdef";
  std::string hex;
  hex.reserve(raw.size() * 2);
  for (unsigned char b : raw) {
    hex.push_back(K_HEX[b >> 4]);
    hex.push_back(K_HEX[b & 0x0F]);
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

namespace {

// True when `requested_mechanism` names an RSA family mechanism.
bool is_rsa_request(const std::string &mech) {
  return mech.find("RSA") != std::string::npos;
}
// True when it names an EC family mechanism.
bool is_ec_request(const std::string &mech) {
  return mech.find("ECDSA") != std::string::npos;
}
// Enforce policy; throws on RejectMismatch conflict.
void check_family(const std::string &requested_mechanism, bool rsa_key,
                  MechanismPolicy policy) {
  if (requested_mechanism.empty() ||
      policy == MechanismPolicy::AllowNativeFallback)
    return;
  const bool conflict =
      rsa_key ? is_ec_request(requested_mechanism)
              : is_rsa_request(requested_mechanism);
  if (conflict) {
    throw std::runtime_error(
        "CKR_KEY_TYPE_INCONSISTENT: mechanism " + requested_mechanism +
        " does not match " + (rsa_key ? "RSA" : "EC") + " key");
  }
}

} // namespace

SignResult CryptoEngine::sign(const RSAKeyPair &key,
                              const std::vector<u8> &data,
                              const std::string &requested_mechanism,
                              MechanismPolicy policy) {
  VHSM_CHECK_MSG(key.key != nullptr, "CryptoEngine::sign: key is null");
  check_family(requested_mechanism, /*rsa_key=*/true, policy);
  return make_result(RSAUtil::sign(key, data), data, "CKM_SHA256_RSA_PKCS");
}

SignResult CryptoEngine::sign(const ECCKeyPair &key,
                              const std::vector<u8> &data,
                              const std::string &requested_mechanism,
                              MechanismPolicy policy) {
  VHSM_CHECK_MSG(key.key != nullptr, "CryptoEngine::sign: key is null");
  check_family(requested_mechanism, /*rsa_key=*/false, policy);
  return make_result(ECC::sign(key, data), data, "CKM_ECDSA_SHA256");
}
} // namespace vhsm::crypto
