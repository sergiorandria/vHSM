#ifndef FABRIC_CRYPTO_X509_H
#define FABRIC_CRYPTO_X509_H

#include <string>
#include <vector>
#include <chrono>

namespace fabric {
namespace crypto {

/**
 * X.509 certificate parsing and validation utilities
 */
class X509Certificate {
public:
    /**
     * Parse an X.509 certificate from PEM format
     * @param certPEM Certificate in PEM format
     */
    explicit X509Certificate(const std::string& certPEM);
    
    // Destructor
    ~X509Certificate() = default;

    /**
     * Get the certificate in PEM format
     * @return Certificate as PEM string
     */
    std::string getPEM() const;

    /**
     * Get the subject common name
     * @return Common Name from subject
     */
    std::string getSubjectCommonName() const;

    /**
     * Get the issuer information
     * @return Issuer string
     */
    std::string getIssuer() const;

    /**
     * Get the serial number
     * @return Serial number as hex string
     */
    std::string getSerialNumber() const;

    /**
     * Get the not-before timestamp
     * @return Validity start time
     */
    std::chrono::system_clock::time_point getNotBefore() const;

    /**
     * Get the not-after timestamp
     * @return Validity end time
     */
    std::chrono::system_clock::time_point getNotAfter() const;

    /**
     * Check if the certificate is currently valid
     * @return True if certificate is valid (within validity period)
     */
    bool isValid() const;

    /**
     * Get the public key from the certificate
     * @return Public key in PEM format
     */
    std::string getPublicKeyPEM() const;

    /**
     * Extract Subject Alternative Names (SANs)
     * @return Vector of SAN strings
     */
    std::vector<std::string> getSubjectAlternativeNames() const;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace crypto
} // namespace fabric

#endif // FABRIC_CRYPTO_X509_H