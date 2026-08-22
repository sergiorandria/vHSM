#ifndef FABRIC_IDENTITY_IDENTITY_H
#define FABRIC_IDENTITY_IDENTITY_H

#include <string>

#include "fabric/crypto/secure_string.h"

namespace fabric {
namespace identity {

/**
 * Represents a Fabric identity comprising MSP ID, certificate, and private key
 */
class Identity {
public:
  /**
   * Create an identity from components
   * @param mspId MSP Identifier
   * @param cert PEM-encoded certificate
   * @param key PEM-encoded private key
   */
  Identity(const std::string &mspId, const std::string &cert,
            const std::string &key);

  // Overload that takes ownership of an already self-wiping key buffer.  Used
  // on the enrollment path so the freshly generated private key never exists
  // as a plaintext std::string copy that would outlive the Identity unwiped.
  Identity(const std::string &mspId, const std::string &cert,
            crypto::SecureString key);

  /**
   * Get the MSP ID
   * @return MSP identifier
   */
  const std::string &getMSPID() const;

  /**
   * Get the certificate in PEM format
   * @return PEM-encoded certificate
   */
  const std::string &getCertificate() const;

  /**
   * Get the private key in PEM format
   * @return PEM-encoded private key
   */
  const std::string &getPrivateKey() const;

  /**
   * Check if the identity is valid (has all required components)
   * @return True if identity is valid
   */
  bool isValid() const;

private:
  std::string mspId_;
  std::string certificate_;
  // Private key material is held in a self-wiping buffer, not a plain
  // std::string: the key must not outlive the Identity in plaintext. The cert
  // is public, so it stays a normal string.
  crypto::SecureString privateKey_;
};

} // namespace identity
} // namespace fabric

#endif // FABRIC_IDENTITY_IDENTITY_H