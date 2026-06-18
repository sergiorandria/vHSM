#ifndef FABRIC_CRYPTO_CSR_H
#define FABRIC_CRYPTO_CSR_H

#include <string>
#include <vector>

namespace fabric {
namespace crypto {

/**
 * Certificate Signing Request (PKCS#10) utilities
 */
class CSR {
public:
    /**
     * Generate a CSR from a private key and subject information
     * @param privateKeyPEM Private key in PEM format
     * @param commonName Common Name for the certificate
     * @param organization Organization name (optional)
     * @param organizationalUnit Organizational unit (optional)
     * @param locality Locality (optional)
     * @param state State or province (optional)
     * @param country Country code (optional)
     * @param sans Subject Alternative Names (optional)
     * @return CSR in PEM format
     */
    static std::string generate(
        const std::string& privateKeyPEM,
        const std::string& commonName,
        const std::string& organization = "",
        const std::string& organizationalUnit = "",
        const std::string& locality = "",
        const std::string& state = "",
        const std::string& country = "",
        const std::vector<std::string>& sans = {}
    );

    /**
     * Parse a CSR and extract the public key
     * @param csrPEM CSR in PEM format
     * @return Public key extracted from the CSR in PEM format
     */
    static std::string extractPublicKey(const std::string& csrPEM);

    /**
     * Validate a CSR signature
     * @param csrPEM CSR in PEM format
     * @return True if CSR is valid
     */
    static bool validate(const std::string& csrPEM);
};

} // namespace crypto
} // namespace fabric

#endif // FABRIC_CRYPTO_CSR_H