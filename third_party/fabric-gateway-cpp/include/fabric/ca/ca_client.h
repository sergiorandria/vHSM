#ifndef FABRIC_CA_CA_CLIENT_H
#define FABRIC_CA_CA_CLIENT_H

#include "../../../include/fabric/ca/httptypes.h"
#include "../../../include/fabric/crypto/x509.h"
#include "../../../include/fabric/identity/identity.h"
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace fabric {
namespace identity {
class Identity;
}
} // namespace fabric

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
   * @param mspId MSP ID assigned to identities returned by enroll()/reenroll()
   */
  CaClient(std::shared_ptr<HttpClient> httpClient, const std::string &caUrl,
           const std::optional<std::string> &caCertPath = std::nullopt,
           const std::string &mspId = "SampleMSP");
  ~CaClient();

  /**
   * Enroll an identity
   * @param enrollmentId Enrollment ID
   * @param enrollmentSecret Enrollment secret
   * @param profile Optional profile name
   * @param labels Optional labels to associate with the identity
   * @param attrReqs Optional attribute requests
   * @param type Optional type (default: "user")
   * @return Enrolled identity (MSP ID, certificate, private key)
   *
   * Generates a fresh EC keypair and CSR locally, submits the CSR to the CA
   * over Basic auth, and returns an Identity whose certificate matches the
   * generated private key.
   */
  identity::Identity
  enroll(const std::string &enrollmentId, const std::string &enrollmentSecret,
         const std::optional<std::string> &profile = std::nullopt,
         const std::optional<std::vector<std::string>> &labels = std::nullopt,
         const std::optional<std::vector<std::string>> &attrReqs = std::nullopt,
         const std::optional<std::string> &type = std::nullopt);

  /**
   * Register a new identity
   * @param registrar Enrolled identity that performs the registration; its
   *                  certificate and private key are used to sign the request
   *                  token (fabric-ca does not accept basic auth here)
   * @param id Name of the identity to register
   * @param type Type of identity (default: "user")
   * @param maxEnrollments Maximum number of enrollments (default: -1 for
   * unlimited)
   * @param nodeRole Whether the identity can be a node (optional)
   * @param account Whether the identity can be an account (optional)
   * @param affiliation Affiliation of the identity (optional)
   * @param attributes Attributes to associate with the identity (optional)
   * @param caName Name of the CA (optional)
   * @param secret Optional secret (if not provided, one will be generated)
   * @return Registration response containing the secret
   */
  struct RegisterResponse {
    std::string secret;   // The enrollment secret
    std::string password; // Alternative to secret (for compatibility)
    std::string enrollmentID;
    std::string type;
    std::string affiliation;
    std::vector<std::string> attributes;
  };

  RegisterResponse registerIdentity(
      const identity::Identity &registrar, const std::string &id,
      const std::optional<std::string> &type = std::nullopt,
      const std::optional<int> &maxEnrollments = std::nullopt,
      const std::optional<bool> &nodeRole = std::nullopt,
      const std::optional<bool> &account = std::nullopt,
      const std::optional<std::string> &affiliation = std::nullopt,
      const std::optional<std::vector<std::string>> &attributes = std::nullopt,
      const std::optional<std::string> &caName = std::nullopt,
      const std::optional<std::string> &secret = std::nullopt);

  /**
   * Reenroll an identity (a new certificate for its existing key material)
   * @param identity Identity to reenroll; its certificate and private key
   *                 authenticate the request and its key material is reused
   * @return New identity with updated certificate
   */
  identity::Identity reenroll(const identity::Identity &identity);

  /**
   * Revoke an identity or certificate
   * @param registrar Enrolled identity that performs the revocation (must have
   *                  the hf.Revoker attribute); authenticates via token
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

  RevokeResponse revoke(const identity::Identity &registrar,
                        const std::string &name,
                        const std::optional<std::string> &aki = std::nullopt,
                        const std::optional<std::string> &serial = std::nullopt,
                        const std::optional<std::string> &reason = std::nullopt,
                        const std::optional<bool> &genCRL = std::nullopt);

  /**
   * Get CA information
   * @return CA information including version, chain, etc.
   */
  struct CaInfoResponse {
    std::string version;              // CA version
    std::string caName;               // CA name on the server
    std::vector<std::string> caChain; // Certificate chain (PEM certs)
    std::vector<std::string> caCerts; // CA certificates (alias of caChain)
  };

  CaInfoResponse getCAInfo();

  /**
   * Get certificates from the CA
   * @param registrar Enrolled identity performing the query; authenticates via
   *                  token (fabric-ca does not accept basic auth here)
   * @param aki Optional Authority Key Identifier filter
   * @param serial Optional serial number filter
   * @param authorityKeyIdentifier Optional authority key identifier filter
   * @return Matching certificates
   */
  std::vector<std::string> getCertificates(
      const identity::Identity &registrar,
      const std::optional<std::string> &aki = std::nullopt,
      const std::optional<std::string> &serial = std::nullopt,
      const std::optional<std::string> &authorityKeyIdentifier = std::nullopt);

private:
  std::shared_ptr<HttpClient> httpClient_;
  std::string caUrl_;
  std::optional<std::string> caCertPath_;
  std::string mspId_;

  // Helper methods
  std::string buildUrl(const std::string &endpoint) const;

  // Builds the headers every authenticated CA request needs:
  // Content-Type: application/json and Authorization: Basic base64(id:secret).
  static std::vector<std::pair<std::string, std::string>>
  authHeaders(const std::string &enrollmentId,
              const std::string &enrollmentSecret);

  // Builds the headers a token-authenticated request needs:
  // Content-Type: application/json and
  // Authorization: <b64(certPEM)>.<b64(ECDSA-sig over method.uri.body.cert)>.
  // fabric-ca requires this scheme for register/revoke/certificates/etc.
  std::vector<std::pair<std::string, std::string>>
  tokenHeaders(const identity::Identity &registrar, const std::string &method,
               const std::string &uri, const std::string &body) const;

  // Generates the authorization token for the given registrar identity over
  // method + "." + b64(uri) + "." + b64(body) + "." + b64(cert).
  std::string buildToken(const identity::Identity &registrar,
                         const std::string &method, const std::string &uri,
                         const std::string &body) const;

  std::string parseCertFromResponse(const std::string &response);
  std::vector<std::string>
  parseCertChainFromResponse(const std::string &response);

  // Generates a fresh EC keypair + CSR, submits it to `endpoint`, and
  // returns {certificatePEM, privateKeyPEM}.  The private key stays in a
  // self-wiping buffer (crypto::SecureString) so it is never exposed as a
  // plaintext std::string copy on the enrollment path.
  std::pair<std::string, crypto::SecureString> enrollCommon(
      const std::string &enrollmentId, const std::string &enrollmentSecret,
      const std::string &endpoint,
      const std::optional<std::string> &profile = std::nullopt,
      const std::optional<std::vector<std::string>> &attrReqs = std::nullopt);
};
} // namespace ca
} // namespace fabric

#endif // FABRIC_CA_CA_CLIENT_H