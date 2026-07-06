#ifndef FABRIC_IDENTITY_IDENTITY_H
#define FABRIC_IDENTITY_IDENTITY_H

#include <string>

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
    Identity(const std::string& mspId, const std::string& cert, const std::string& key);

    /**
     * Get the MSP ID
     * @return MSP identifier
     */
    const std::string& getMSPID() const;

    /**
     * Get the certificate in PEM format
     * @return PEM-encoded certificate
     */
    const std::string& getCertificate() const;

    /**
     * Get the private key in PEM format
     * @return PEM-encoded private key
     */
    const std::string& getPrivateKey() const;

    /**
     * Check if the identity is valid (has all required components)
     * @return True if identity is valid
     */
    bool isValid() const;

private:
    std::string mspId_;
    std::string certificate_;
    std::string privateKey_;
};

} // namespace identity
} // namespace fabric

#endif // FABRIC_IDENTITY_IDENTITY_H