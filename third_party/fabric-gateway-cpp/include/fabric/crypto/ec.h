#ifndef FABRIC_CRYPTO_EC_H
#define FABRIC_CRYPTO_EC_H

#include <memory>
#include <string>

#include "fabric/crypto/secure_string.h"

namespace fabric {
namespace crypto {

/**
 * Elliptic Curve cryptography utilities for Hyperledger Fabric
 * Uses P-256 curve (secp256r1) as Fabric's default
 */
class ECKeyPair {
public:
  /**
   * Generate a new EC key pair using P-256 curve
   * @return Pair of (privateKeyPEM, publicKeyPEM) as strings
   */
  static std::pair<SecureString, std::string> generate();

  /**
   * Load a private key from PEM format
   * @param pem Private key in PEM format
   */
  explicit ECKeyPair(const std::string &pem);

  ~ECKeyPair();

  /**
   * Get the private key in PEM format
   * @return Private key as PEM string
   */
  SecureString getPrivateKeyPEM() const;

  /**
   * Get the public key in PEM format
   * @return Public key as PEM string
   */
  std::string getPublicKeyPEM() const;

  /**
   * Sign data using ECDSA
   * @param data Data to sign
   * @return Signature as hex string
   */
  std::string sign(const std::string &data) const;

  /**
   * Sign a message digest (SHA-256 output, not the message itself) using ECDSA
   * and return a DER-encoded (ASN.1 SEQUENCE{ R, S }) signature with low-S
   * enforced.  This matches the scheme Hyperledger Fabric uses for its
   * transaction and registry token signatures.
   * @param digest Digest bytes to sign (typically a SHA-256 hash)
   * @return DER-encoded ECDSA signature bytes
   */
  std::string signDigest(const std::string &digest) const;

  /**
   * Verify a signature
   * @param data Data that was signed
   * @param signature Hex-encoded signature
   * @return True if signature is valid
   */
  bool verify(const std::string &data, const std::string &signature) const;

private:
  class Impl;
  std::unique_ptr<Impl> pimpl_;
};

} // namespace crypto
} // namespace fabric

#endif // FABRIC_CRYPTO_EC_H