#include "../../../include/fabric/ca/ca_client.h"
#include "../../../include/fabric/ca/ca_client.h"
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>

using json = nlohmann::json;

namespace fabric {
namespace ca {

CaClient::CaClient(std::shared_ptr<HttpClient> httpClient,
                   const std::string& caUrl,
                   const std::optional<std::string>& caCertPath)
    : httpClient_(std::move(httpClient)), caUrl_(caUrl), caCertPath_(caCertPath) {
    // Remove trailing slash from caUrl if present
    if (!caUrl_.empty() && caUrl_.back() == '/') {
        caUrl_.pop_back();
    }

    // Configure TLS options if CA cert is provided
    if (caCertPath_.has_value()) {
        httpClient_->setTLSOptions(caCertPath_);
    }
}

CaClient::~CaClient() = default;

std::string CaClient::buildUrl(const std::string& endpoint) const {
    return caUrl_ + endpoint;
}

std::string CaClient::parseCertFromResponse(const std::string& response) {
    try {
        auto j = json::parse(response);
        if (j.contains("cert") && !j["cert"].is_null()) {
            return j["cert"].get<std::string>();
        }
        if (j.contains("result") && j["result"].is_array() && !j["result"].empty()) {
            auto& result0 = j["result"][0];
            if (result0.contains("cert") && !result0["cert"].is_null()) {
                return result0["cert"].get<std::string>();
            }
        }
        throw std::runtime_error("No certificate found in CA response");
    } catch (const json::exception& e) {
        throw std::runtime_error("Failed to parse CA response: " + std::string(e.what()));
    }
}

std::vector<std::string> CaClient::parseCertChainFromResponse(const std::string& response) {
    try {
        auto j = json::parse(response);
        std::vector<std::string> chain;

        if (j.contains("cert") && !j["cert"].is_null()) {
            chain.push_back(j["cert"].get<std::string>());
        }

        if (j.contains("caChain") && j["caChain"].is_array()) {
            for (const auto& cert : j["caChain"]) {
                if (!cert.is_null()) {
                    chain.push_back(cert.get<std::string>());
                }
            }
        } else if (j.contains("result") && j["result"].is_array()) {
            for (const auto& resultItem : j["result"]) {
                if (resultItem.contains("cert") && !resultItem["cert"].is_null()) {
                    chain.push_back(resultItem["cert"].get<std::string>());
                }
                if (resultItem.contains("caChain") && resultItem["caChain"].is_array()) {
                    for (const auto& cert : resultItem["caChain"]) {
                        if (!cert.is_null()) {
                            chain.push_back(cert.get<std::string>());
                        }
                    }
                }
            }
        }

        return chain;
    } catch (const json::exception& e) {
        throw std::runtime_error("Failed to parse CA certificate chain: " + std::string(e.what()));
    }
}

std::string CaClient::enrollCommon(const std::string& enrollmentId,
                                  const std::string& enrollmentSecret,
                                  const std::string& endpoint,
                                  const std::optional<std::string>& profile,
                                  const std::optional<std::vector<std::string>>& labels,
                                  const std::optional<std::vector<std::string>>& attrReqs,
                                  const std::optional<std::string>& type,
                                  const std::optional<int>& reqType) {
    // Build request body
    json req;
    req["enrollmentID"] = enrollmentId;
    req["enrollmentSecret"] = enrollmentSecret;

    if (profile.has_value()) {
        req["profile"] = profile.value();
    }
    if (labels.has_value()) {
        req["labels"] = labels.value();
    }
    if (attrReqs.has_value()) {
        json attrReqJson;
        for (const auto& attr : attrReqs.value()) {
            attrReqJson.push_back({{"name", attr}, {"optional", false}});
        }
        req["attr_reqs"] = attrReqJson;
    }
    if (type.has_value()) {
        req["type"] = type.value();
    }
    if (reqType.has_value()) {
        req["type"] = reqType.value(); // Override type if reqType is specified
    }

    // Make HTTP request
    auto response = httpClient_->request(
        HttpMethod::POST,
        buildUrl(endpoint),
        {}, // headers - could add Content-Type: application/json
        req.dump(),
        30 // timeout
    );

    if (response.statusCode != 200 && response.statusCode != 201) {
        throw std::runtime_error("CA request failed with status: " +
                                std::to_string(response.statusCode) +
                                ", body: " + response.body);
    }

    // Parse response and return certificate
    return parseCertFromResponse(response.body);
}

identity::Identity CaClient::enroll(const std::string& enrollmentId,
                          const std::string& enrollmentSecret,
                          const std::optional<std::string>& profile,
                          const std::optional<std::vector<std::string>>& labels,
                          const std::optional<std::vector<std::string>>& attrReqs,
                          const std::optional<std::string>& type) {
    // Generate a new key pair for enrollment
    // In a real implementation, this would use the crypto library to generate a key pair
    // For now, we'll simulate this by returning a placeholder
    // TODO: Implement actual key generation using OpenSSL

    std::string cert = enrollCommon(enrollmentId, enrollmentSecret, "/api/v1/enroll",
                                   profile, labels, attrReqs, type, std::nullopt);

    // Extract MSP ID from CA (in a real implementation, this would come from CA config)
    std::string mspId = "SampleMSP"; // TODO: Get from CA info

    // For private key, in a real implementation we would return the actual generated key
    // For now, we'll return a placeholder
    std::string privateKey = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD...\n-----END PRIVATE KEY-----";

    return identity::Identity(mspId, cert, privateKey);
}

CaClient::RegisterResponse CaClient::registerIdentity(const std::string& enrollmentId,
                                                     const std::string& enrollmentSecret,
                                                     const std::string& id,
                                                     const std::optional<std::string>& type,
                                                     const std::optional<int>& maxEnrollments,
                                                     const std::optional<bool>& nodeRole,
                                                     const std::optional<bool>& account,
                                                     const std::optional<std::string>& affiliation,
                                                     const std::optional<std::vector<std::string>>& attributes,
                                                     const std::optional<std::string>& caName,
                                                     const std::optional<std::string>& secret) {
    json req;
    req["enrollmentID"] = enrollmentId;
    req["enrollmentSecret"] = enrollmentSecret;
    req["id"] = id;

    if (type.has_value()) {
        req["type"] = type.value();
    }
    if (maxEnrollments.has_value()) {
        req["max_enrollments"] = maxEnrollments.value();
    }
    if (nodeRole.has_value()) {
        req["node_role"] = nodeRole.value();
    }
    if (account.has_value()) {
        req["account"] = account.value();
    }
    if (affiliation.has_value()) {
        req["affiliation"] = affiliation.value();
    }
    if (attributes.has_value()) {
        req["attributes"] = attributes.value();
    }
    if (caName.has_value()) {
        req["caname"] = caName.value();
    }
    if (secret.has_value()) {
        req["secret"] = secret.value();
    }

    auto response = httpClient_->request(
        HttpMethod::POST,
        buildUrl("/api/v1/register"),
        {},
        req.dump(),
        30
    );

    if (response.statusCode != 200 && response.statusCode != 201) {
        throw std::runtime_error("CA register failed with status: " +
                                std::to_string(response.statusCode) +
                                ", body: " + response.body);
    }

    try {
        auto j = json::parse(response.body);
        RegisterResponse resp;
        if (j.contains("secret")) {
            resp.secret = j["secret"].get<std::string>();
        }
        if (j.contains("password")) {
            resp.password = j["password"].get<std::string>();
        }
        if (j.contains(" enrollmentID")) {
            resp.enrollmentID = j["enrollmentID"].get<std::string>();
        }
        if (j.contains("type")) {
            resp.type = j["type"].get<std::string>();
        }
        if (j.contains("affiliation")) {
            resp.affiliation = j["affiliation"].get<std::string>();
        }
        if (j.contains("attributes")) {
            resp.attributes = j["attributes"].get<std::vector<std::string>>();
        }
        return resp;
    } catch (const json::exception& e) {
        throw std::runtime_error("Failed to parse CA register response: " + std::string(e.what()));
    }
}

identity::Identity CaClient::reenroll(const std::string& enrollmentId) {
    // Reenroll uses the same endpoint as enroll but with different semantics
    // In practice, it would use the existing identity for authentication
    // For simplicity, we'll call enroll with a special endpoint

    // TODO: Implement proper reenrollment using existing credentials
    // For now, we'll treat it as a regular enroll (this is a simplification)

    std::string cert = enrollCommon(enrollmentId, "", "/api/v1/reenroll",
                                   std::nullopt, std::nullopt, std::nullopt,
                                   std::nullopt, 2); // reqType=2 for reenroll

    std::string mspId = "SampleMSP"; // TODO: Get from CA info or existing identity
    std::string privateKey = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD...\n-----END PRIVATE KEY-----";

    return identity::Identity(mspId, cert, privateKey);
}

CaClient::RevokeResponse CaClient::revoke(const std::string& enrollmentId,
                                         const std::string& enrollmentSecret,
                                         const std::string& name,
                                         const std::optional<std::string>& aki,
                                         const std::optional<std::string>& serial,
                                         const std::optional<std::string>& reason,
                                         const std::optional<bool>& genCRL) {
    json req;
    req["enrollmentID"] = enrollmentId;
    req["enrollmentSecret"] = enrollmentSecret;
    req["name"] = name;

    if (aki.has_value()) {
        req["aki"] = aki.value();
    }
    if (serial.has_value()) {
        req["serial"] = serial.value();
    }
    if (reason.has_value()) {
        req["reason"] = reason.value();
    }
    if (genCRL.has_value()) {
        req["gen_crl"] = genCRL.value();
    }

    auto response = httpClient_->request(
        HttpMethod::POST,
        buildUrl("/api/v1/revoke"),
        {},
        req.dump(),
        30
    );

    if (response.statusCode != 200 && response.statusCode != 201) {
        throw std::runtime_error("CA revoke failed with status: " +
                                std::to_string(response.statusCode) +
                                ", body: " + response.body);
    }

    try {
        auto j = json::parse(response.body);
        RevokeResponse resp;
        if (j.contains("revokedCertificates")) {
            resp.revokedCertificates = j["revokedCertificates"].get<std::string>();
        }
        if (j.contains("crl")) {
            resp.crl = j["crl"].get<std::string>();
        }
        return resp;
    } catch (const json::exception& e) {
        throw std::runtime_error("Failed to parse CA revoke response: " + std::string(e.what()));
    }
}

CaClient::CaInfoResponse CaClient::getCAInfo() {
    auto response = httpClient_->request(
        HttpMethod::GET,
        buildUrl("/api/v1/cainfo"),
        {},
        std::nullopt,
        30
    );

    if (response.statusCode != 200) {
        throw std::runtime_error("CA info failed with status: " +
                                std::to_string(response.statusCode) +
                                ", body: " + response.body);
    }

    try {
        auto j = json::parse(response.body);
        CaInfoResponse resp;
        if (j.contains("version")) {
            resp.version = j["version"].get<std::string>();
        }
        if (j.contains("caChain")) {
            resp.caChain = j["caChain"].get<std::vector<std::string>>();
        }
        if (j.contains("caCerts")) {
            resp.caCerts = j["caCerts"].get<std::vector<std::string>>();
        }
        return resp;
    } catch (const json::exception& e) {
        throw std::runtime_error("Failed to parse CA info response: " + std::string(e.what()));
    }
}

std::vector<std::string> CaClient::getCertificates(const std::optional<std::string>& aki,
                                                  const std::optional<std::string>& serial,
                                                  const std::optional<std::string>& authorityKeyIdentifier) {
    json req;
    if (aki.has_value()) {
        req["aki"] = aki.value();
    }
    if (serial.has_value()) {
        req["serial"] = serial.value();
    }
    if (authorityKeyIdentifier.has_value()) {
        req["authority_key_identifier"] = authorityKeyIdentifier.value();
    }

    auto response = httpClient_->request(
        HttpMethod::POST,
        buildUrl("/api/v1/cacerts"),
        {},
        req.dump(),
        30
    );

    if (response.statusCode != 200) {
        throw std::runtime_error("CA certs failed with status: " +
                                std::to_string(response.statusCode) +
                                ", body: " + response.body);
    }

    try {
        auto j = json::parse(response.body);
        if (j.is_array()) {
            std::vector<std::string> certs;
            for (const auto& cert : j) {
                if (!cert.is_null() && cert.is_string()) {
                    certs.push_back(cert.get<std::string>());
                }
            }
            return certs;
        }

        // Handle case where response is an object with a certificates array
        if (j.contains("certificates") && j["certificates"].is_array()) {
            std::vector<std::string> certs;
            for (const auto& cert : j["certificates"]) {
                if (!cert.is_null() && cert.is_string()) {
                    certs.push_back(cert.get<std::string>());
                }
            }
            return certs;
        }

        return {};
    } catch (const json::exception& e) {
        throw std::runtime_error("Failed to parse CA certificates response: " + std::string(e.what()));
    }
}

} // namespace ca
} // namespace fabric