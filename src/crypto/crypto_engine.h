/*
 * crypto_engine.h
 *
 * CryptoEngine is the single entry point that the PKCS#11 signing path
 * (C_Sign / C_SignFinal) and any other caller should use to produce a
 * signature. It selects RSA or ECDSA based on the key type and records what
 * was actually used in SignResult::mechanism_str.
 *
 * Keys are opaque scrypto-backed handles (see rsa.h / ecc.h). All symmetric
 * and asymmetric primitives come from vhsm::scrypto.
 */

#pragma once

#include "../domain/core/kernel_types.h"
#include "../domain/crypto/crypto_types.h"
#include "ecc.h"
#include "rsa.h"

#include <string>
#include <vector>

namespace vhsm::crypto {

/**
 * What to do when `requested_mechanism` conflicts with the key's algorithm
 * family (e.g. CKM_SHA256_RSA_PKCS requested for an EC key).
 *
 * RejectMismatch (default) — PKCS#11-conformant: the caller gets a failure
 *   carrying CKR_KEY_TYPE_INCONSISTENT instead of a signature it may verify
 *   under the wrong algorithm. This is what C_SignInit must do.
 * AllowNativeFallback — explicit opt-in for legacy callers that want the key's
 *   native algorithm; SignResult::mechanism_str then records the algorithm
 *   ACTUALLY used, never the requested one.
 */
enum class MechanismPolicy {
  RejectMismatch,
  AllowNativeFallback,
};

class CryptoEngine {
public:
  /**
   * Sign `data` with `key`, hashing with SHA-256.
   *
   * Fail-closed: if `requested_mechanism` names an algorithm family that does
   * not match the key type and policy is RejectMismatch (the default), this
   * throws with CKR_KEY_TYPE_INCONSISTENT in the message — matching PKCS#11
   * semantics where silent algorithm substitution is forbidden.
   *
   * @param key                   RSAKeyPair or ECCKeyPair handle. Not owned.
   * @param data                  Raw message bytes to be hashed and signed.
   * @param requested_mechanism   Mechanism the caller asked for (audit hint).
   *                              Empty string = native algorithm, no check.
   * @param policy                Mismatch handling; see MechanismPolicy.
   *
   * @return SignResult carrying the signature, digest, and mechanism used.
   *   mechanism_str ALWAYS reflects the algorithm actually used.
   */
  static SignResult sign(const RSAKeyPair &key, const std::vector<u8> &data,
                         const std::string &requested_mechanism = "",
                         MechanismPolicy policy = MechanismPolicy::RejectMismatch);
  static SignResult sign(const ECCKeyPair &key, const std::vector<u8> &data,
                         const std::string &requested_mechanism = "",
                         MechanismPolicy policy = MechanismPolicy::RejectMismatch);
};

} // namespace vhsm::crypto
