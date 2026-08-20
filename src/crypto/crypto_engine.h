/*
 * crypto_engine.h
 *
 * CryptoEngine is the single entry point that the PKCS#11 signing path
 * (C_Sign / C_SignFinal) and any other caller should use to produce a
 * signature. It selects RSA or ECDSA based on the key type and supports a
 * fail-closed fallback: an incompatible or unspecified mechanism string does
 * not abort the operation, it signs with the key's native algorithm and
 * records what was actually used in SignResult::mechanism_str.
 *
 * WHY CryptoEngine is a single orchestration point: All signing in vHSM flows
 * through this class. This centralizes policy:
 *   - Mechanism selection (which algorithm for this key type?)
 *   - Digest computation (always SHA-256)
 *   - Fallback behavior (incompatible request → use native algorithm)
 *   - Auditability (mechanism_str recorded in SignResult)
 * By funneling all signatures here, we prevent bypasses and ensure consistent
 * behavior.
 *
 * WHY fail-closed on mechanism mismatch: vHSM must never silently produce a
 * wrong-algorithm signature. If a caller requests RSA-PKCS but passes an EC
 * key, we don't fail (transaction aborts). Instead, we sign with the key's
 * native algorithm (ECDSA) and record the actual mechanism in SignResult. This
 * ensures:
 *   1. The signature succeeds (availability)
 *   2. The ledger reveals what was actually signed with (auditability)
 *   3. Applications can detect the mismatch and log/alert (visibility)
 */

#pragma once

#include "../core/types.h"

#include <openssl/evp.h>

#include <string>
#include <vector>

namespace vhsm::crypto {

class CryptoEngine {
public:
  /**
   * Sign `data` with `key`, hashing with SHA-256.
   *
   * @param key                   OpenSSL EVP_PKEY (RSA or EC). Not owned.
   *                              Caller retains ownership and lifetime
   * responsibility.
   * @param data                  Raw message bytes to be hashed and signed.
   * @param requested_mechanism   Optional mechanism hint such as
   *                              "CKM_SHA256_RSA_PKCS" or "CKM_ECDSA_SHA256".
   *                              When it conflicts with the key type, the
   *                              engine falls back to the key's native
   *                              algorithm instead of failing.
   *
   * WHY requested_mechanism is a string hint, not enforced: PKCS#11
   * applications pass mechanism IDs (CKM_*). We accept a string for clarity in
   * logs, but treat it as a hint. If the hint is incompatible with the key
   * type, we ignore it and sign with the key's native algorithm. This is
   * fail-closed: the signature always succeeds, but the ledger records what was
   * actually used. Callers who care can inspect SignResult::mechanism_str to
   * detect mismatches.
   *
   * @return SignResult carrying the signature, the digest, and the mechanism
   *         that was actually applied (for auditability). If the requested
   * mechanism doesn't match the key type, mechanism_str contains the actual
   * mechanism used.
   */
  static SignResult sign(EVP_PKEY *key, const std::vector<u8> &data,
                         const std::string &requested_mechanism = "");
};

} // namespace vhsm::crypto
