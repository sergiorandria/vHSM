#ifndef FABRIC_CA_CA_CLIENT_H
#define FABRIC_CA_CA_CLIENT_H

#include <string>
#include <vector>
#include <memory>
#include <optional>
#include "../../../include/fabric/ca/httptypes.h"
#include "../../../include/fabric/identity/identity.h"
#include "../../../include/fabric/crypto/x509.h"

namespace fabric {
namespace identity {
class Identity;
}
}

namespace fabric {
namespace ca {

/**
 * Fabric CA client for identity management operations
 */
class CaClient {
public:
    /**
     * Create a CA client
     * @param httpClient HTTP client implementation to use
     * @param caUrl Base URL of the Fabric CA server
     * @param caCertPath Optional path to CA certificate for TLS verification
     */
    CaClient(std::shared_ptr<HttpClient> httpClient,
             const std::string& caUrl,
             const std::optional<std::string>& caCertPath = std::nullopt);
    ~CaClient();

    /**
     * Enroll an identity (register and enroll in one step)
     * @param enrollmentId Enrollment ID
     * @param enrollmentSecret Enrollment secret
     * @param profile Optional profile name
     * @param labels Optional labels to associate with the identity
     * @param attrReqs Optional attribute requests
     * @param type Optional type (default: "user")
     * @return Enrolled identity (MSP ID, certificate, private key)
     */
    identity::Identity enroll(const std::string& enrollmentId,
                    const std::string& enrollmentSecret,
                    const std::optional<std::string>& profile = std::nullopt,
                    const std::optional<std::vector<std::string>>& labels = std::nullopt,
                    const std::optional<std::vector<std::string>>& attrReqs = std::nullopt,
                    const std::optional<std::string>& type = std::nullopt);

    /**
     * Register a new identity
     * @param enrollmentId Enrollment ID of the registrar
     * @param enrollmentSecret Enrollment secret of the registrar
     * @param id Name of the identity to register
     * @param type Type of identity (default: "user")
     * @param maxEnrollments Maximum number of enrollments (default: -1 for unlimited)
     * @param nodeRole Whether the identity can be a node (optional)
     * @param account Whether the identity can be an account (optional)
     * @param affiliation Affiliation of the identity (optional)
     * @param attributes Attributes to associate with the identity (optional)
     * @param caName Name of the CA (optional)
     * @param secret Optional secret (if not provided, one will be generated)
     * @return Registration response containing the secret
     */
    struct RegisterResponse {
        std::string secret;  // The enrollment secret
        std::string password; // Alternative to secret (for compatibility)
        std::string enrollmentID;
        std::string type;
        std::string affiliation;
        std::vector<std::string> attributes;
    };

    RegisterResponse registerIdentity(const std::string& enrollmentId,
                                      const std::string& enrollmentSecret,
                                      const std::string& id,
                                      const std::optional<std::string>& type = std::nullopt,
                                      const std::optional<int>& maxEnrollments = std::nullopt,
                                      const std::optional<bool>& nodeRole = std::nullopt,
                                      const std::optional<bool>& account = std::nullopt,
                                      const std::optional<std::string>& affiliation = std::nullopt,
                                      const std::optional<std::vector<std::string>>& attributes = std::nullopt,
                                      const std::optional<std::string>& caName = std::nullopt,
                                      const std::optional<std::string>& secret = std::nullopt);

    /**
     * Reenroll an identity
     * @param enrollmentId Current enrollment ID
     * @return New identity with updated certificate
     */
    identity::Identity reenroll(const std::string& enrollmentId);

    /**
     * Revoke an identity or certificate
     * @param enrollmentId Enrollment ID of the revoker
     * @param enrollmentSecret Enrollment secret of the revoker
     * @param name Name of the identity to revoke
     * @param aki Authority Key Identifier of the certificate to revoke (optional)
     * @param serial Serial number of the certificate to revoke (optional)
     * @param reason Reason for revocation (optional)
     * @param genCRL Whether to generate a CRL (default: true)
     * @return Revocation response
     */
    struct RevokeResponse {
        std::string revokedCertificates; // List of revoked certificates
        std::string crl;                 // Generated CRL (if requested)
    };

    RevokeResponse revoke(const std::string& enrollmentId,
                          const std::string& enrollmentSecret,
                          const std::string& name,
                          const std::optional<std::string>& aki = std::nullopt,
                          const std::optional<std::string>& serial = std::nullopt,
                          const std::optional<std::string>& reason = std::nullopt,
                          const std::optional<bool>& genCRL = std::nullopt);

    /**
     * Get CA information
     * @return CA information including version, chain, etc.
     */
    struct CaInfoResponse {
        std::string version;           // CA version
        std::vector<std::string> caChain; // Certificate chain
        std::vector<std::string> caCerts; // CA certificates
    };

    CaInfoResponse getCAInfo();

    /**
     * Get certificates from the CA
     * @param aki Optional Authority Key Identifier filter
     * @param serial Optional serial number filter
     * @param authorityKeyIdentifier Optional authority key identifier filter
     * @return Matching certificates
     */
    std::vector<std::string> getCertificates(
        const std::optional<std::string>& aki = std::nullopt,
        const std::optional<std::string>& serial = std::nullopt,
        const std::optional<std::string>& authorityKeyIdentifier = std::nullopt);

private:
    std::shared_ptr<HttpClient> httpClient_;
    std::string caUrl_;
    std::optional<std::string> caCertPath_;

    // Helper methods
    std::string buildUrl(const std::string& endpoint) const;
    std::string parseCertFromResponse(const std::string& response);
    std::vector<std::string> parseCertChainFromResponse(const std::string& response);
    std::string enrollCommon(const std::string& enrollmentId,
                            const std::string& enrollmentSecret,
                            const std::string& endpoint,
                            const std::optional<std::string>& profile = std::nullopt,
                            const std::optional<std::vector<std::string>>& labels = std::nullopt,
                            const std::optional<std::vector<std::string>>& attrReqs = std::nullopt,
                            const std::optional<std::string>& type = std::nullopt,
                            const std::optional<int>& reqType = std::nullopt); // 1 for enroll, 2 for reenroll
};
} // namespace ca
} // namespace fabric

#endif // FABRIC_CA_CA_CLIENT_H