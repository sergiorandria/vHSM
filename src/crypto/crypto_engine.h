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

#include "../core/types.h"
#include "ecc.h"
#include "rsa.h"

#include <string>
#include <vector>

namespace vhsm::crypto {

class CryptoEngine {
public:
  /**
   * Sign `data` with `key`, hashing with SHA-256.
   *
   * @param key                   RSAKeyPair or ECCKeyPair handle. Not owned.
   * @param data                  Raw message bytes to be hashed and signed.
   * @param requested_mechanism   Optional mechanism hint; recorded for audit.
   *
   * @return SignResult carrying the signature, digest, and mechanism used.
   */
  static SignResult sign(const RSAKeyPair &key, const std::vector<u8> &data,
                         const std::string &requested_mechanism = "");
  static SignResult sign(const ECCKeyPair &key, const std::vector<u8> &data,
                         const std::string &requested_mechanism = "");
};

} // namespace vhsm::crypto
