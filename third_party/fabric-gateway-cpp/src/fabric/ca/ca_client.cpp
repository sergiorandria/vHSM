#include "../../../include/fabric/ca/ca_client.h"

#include "../../../include/fabric/crypto/csr.h"
#include "../../../include/fabric/crypto/ec.h"
#include "../../../include/fabric/crypto/hash.h"
#include "../../../include/fabric/crypto/x509.h"

#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>

using json = nlohmann::json;

namespace fabric {
namespace ca {

namespace {

// ─────────────────────────────────────────────────────────────────────────────
// small base64 helpers (RFC 4648).  fabric-ca embeds certs/keys as base64.
// ─────────────────────────────────────────────────────────────────────────────

const char kBase64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64Encode(const std::string &in) {
  std::string out;
  out.reserve(((in.size() + 2) / 3) * 4);
  for (std::size_t i = 0; i < in.size(); i += 3) {
    unsigned b0 = static_cast<unsigned char>(in[i]);
    unsigned b1 = i + 1 < in.size() ? static_cast<unsigned char>(in[i + 1]) : 0;
    unsigned b2 = i + 2 < in.size() ? static_cast<unsigned char>(in[i + 2]) : 0;
    out.push_back(kBase64Alphabet[(b0 >> 2) & 0x3F]);
    out.push_back(kBase64Alphabet[((b0 << 4) | (b1 >> 4)) & 0x3F]);
    out.push_back(i + 1 < in.size()
                      ? kBase64Alphabet[((b1 << 2) | (b2 >> 6)) & 0x3F]
                      : '=');
    out.push_back(i + 2 < in.size() ? kBase64Alphabet[b2 & 0x3F] : '=');
  }
  return out;
}

std::string base64Decode(const std::string &in) {
  int table[256];
  for (int &c : table)
    c = -1;
  for (int i = 0; i < 64; ++i) {
    table[static_cast<unsigned char>(kBase64Alphabet[i])] = i;
  }

  std::string out;
  int buffer = 0, bits = 0;
  for (char ch : in) {
    if (ch == '\n' || ch == '\r' || ch == ' ' || ch == '\t' || ch == '=') {
      continue;
    }
    int val = table[static_cast<unsigned char>(ch)];
    if (val < 0) {
      continue; // tolerance for stray chars
    }
    buffer = (buffer << 6) | val;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>((buffer >> bits) & 0xFF));
    }
  }
  return out;
}

// Splits a PEM blob that contains one or more concatenated certificates into
// individual PEM strings (each with its own BEGIN/END header).
std::vector<std::string> splitPemChain(const std::string &blob) {
  std::vector<std::string> result;
  const std::string beginMarker = "-----BEGIN CERTIFICATE-----";
  const std::string endMarker = "-----END CERTIFICATE-----";
  std::size_t pos = 0;
  while (true) {
    auto start = blob.find(beginMarker, pos);
    if (start == std::string::npos)
      break;
    auto end = blob.find(endMarker, start);
    if (end == std::string::npos)
      break;
    end += endMarker.size();
    result.push_back(blob.substr(start, end - start));
    pos = end;
  }
  return result;
}

// Base64-decodes `encoded` when possible; otherwise returns it verbatim
// (some fabric-ca responses return plain PEM under legacy keys).
std::string decodePemField(const json &value) {
  if (value.is_null() || !value.is_string())
    return "";
  std::string s = value.get<std::string>();
  std::string decoded = base64Decode(s);
  // Base64 of PEM always contains the ASCII marker text; use the decoded
  // form when it looks like PEM, else fall back to the raw string.
  if (decoded.find("-----BEGIN") != std::string::npos) {
    return decoded;
  }
  return s;
}

} // namespace

CaClient::CaClient(std::shared_ptr<HttpClient> httpClient,
                   const std::string &caUrl,
                   const std::optional<std::string> &caCertPath,
                   const std::string &mspId)
    : httpClient_(std::move(httpClient)), caUrl_(caUrl),
      caCertPath_(caCertPath), mspId_(mspId) {
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

std::string CaClient::buildUrl(const std::string &endpoint) const {
  return caUrl_ + endpoint;
}

std::vector<std::pair<std::string, std::string>>
CaClient::authHeaders(const std::string &enrollmentId,
                      const std::string &enrollmentSecret) {
  std::vector<std::pair<std::string, std::string>> headers;
  headers.emplace_back("Content-Type", "application/json");
  headers.emplace_back("Accept", "application/json");
  std::string credsBase64 = base64Encode(enrollmentId + ":" + enrollmentSecret);
  headers.emplace_back("Authorization", "Basic " + credsBase64);
  return headers;
}

// fabric-ca requires requests to register/revoke/certificates/... to carry an
// authorization token signed by an *enrolled* registrar identity.  The token is
//   <b64(certPEM)>.<b64(ECDSA raw-low-S signature)>
// where the signature is over SHA-256 of
//   method + "." + b64(uri) + "." + b64(body) + "." + b64(certPEM)
// (uri = request path + query, body = the exact request bytes).
std::string CaClient::buildToken(const identity::Identity &registrar,
                                 const std::string &method,
                                 const std::string &uri,
                                 const std::string &body) const {
  const std::string b64cert = base64Encode(registrar.getCertificate());
  const std::string payload = method + "." + base64Encode(uri) + "." +
                              base64Encode(body) + "." + b64cert;

  crypto::ECKeyPair keypair(registrar.getPrivateKey());
  const std::string sig = keypair.signDigest(crypto::sha256(payload));
  return b64cert + "." + base64Encode(sig);
}

std::vector<std::pair<std::string, std::string>>
CaClient::tokenHeaders(const identity::Identity &registrar,
                       const std::string &method, const std::string &uri,
                       const std::string &body) const {
  std::vector<std::pair<std::string, std::string>> headers;
  headers.emplace_back("Content-Type", "application/json");
  headers.emplace_back("Accept", "application/json");
  headers.emplace_back("Authorization",
                       buildToken(registrar, method, uri, body));
  return headers;
}

std::string CaClient::parseCertFromResponse(const std::string &response) {
  try {
    auto j = json::parse(response);

    // fabric-ca enroll/reenroll returns:
    //   {"result": {"Cert": "<base64 PEM>", "ServerInfo": {...}}}
    if (j.contains("result") && j["result"].is_object()) {
      const auto &result = j["result"];
      if (result.contains("Cert")) {
        std::string pem = decodePemField(result["Cert"]);
        if (!pem.empty())
          return pem;
      }
      if (result.contains("cert")) {
        std::string pem = decodePemField(result["cert"]);
        if (!pem.empty())
          return pem;
      }
    }

    // Legacy top-level shape: {"cert": "..."}
    if (j.contains("cert")) {
      std::string pem = decodePemField(j["cert"]);
      if (!pem.empty())
        return pem;
    }

    throw std::runtime_error("No certificate found in CA response");
  } catch (const json::exception &e) {
    throw std::runtime_error("Failed to parse CA response: " +
                             std::string(e.what()));
  }
}

std::vector<std::string>
CaClient::parseCertChainFromResponse(const std::string &response) {
  try {
    auto j = json::parse(response);
    std::vector<std::string> chain;

    auto collect = [&chain](const json &field) {
      std::string decoded = decodePemField(field);
      if (decoded.empty())
        return;
      auto parts = splitPemChain(decoded);
      if (!parts.empty()) {
        chain.insert(chain.end(), parts.begin(), parts.end());
      } else {
        chain.push_back(decoded);
      }
    };

    if (j.contains("result") && j["result"].is_object()) {
      const auto &result = j["result"];
      if (result.contains("Cert"))
        collect(result["Cert"]);

      // CAChain may live under ServerInfo or directly on result.
      if (result.contains("ServerInfo") && result["ServerInfo"].is_object() &&
          result["ServerInfo"].contains("CAChain")) {
        collect(result["ServerInfo"]["CAChain"]);
      }
      if (result.contains("CAChain"))
        collect(result["CAChain"]);
    } else if (j.contains("caChain") && j["caChain"].is_array()) {
      for (const auto &cert : j["caChain"])
        collect(cert);
    } else if (j.is_array()) {
      for (const auto &item : j)
        collect(item);
    }

    return chain;
  } catch (const json::exception &e) {
    throw std::runtime_error("Failed to parse CA certificate chain: " +
                             std::string(e.what()));
  }
}

std::string extractServerError(const std::string &body) {
  try {
    auto j = json::parse(body);
    if (j.contains("errors") && j["errors"].is_array() &&
        !j["errors"].empty()) {
      const auto &first = j["errors"][0];
      if (first.is_object() && first.contains("message")) {
        return first["message"].get<std::string>();
      }
    }
  } catch (...) {
    // not JSON; ignore
  }
  return body;
}

std::pair<std::string, crypto::SecureString> CaClient::enrollCommon(
    const std::string &enrollmentId, const std::string &enrollmentSecret,
    const std::string &endpoint, const std::optional<std::string> &profile,
    const std::optional<std::vector<std::string>> &attrReqs) {
  // 1. Generate a fresh EC keypair and a PKCS#10 CSR for it.  The CA binds
  //    the issued certificate to this CSR's public key, so the returned
  //    Identity's private key matches the certificate.
  auto [privateKeyPEM, publicKeyPEM] = crypto::ECKeyPair::generate();
  std::string csrPEM = crypto::CSR::generate(privateKeyPEM.str(), enrollmentId);

  // 2. Build the fabric-ca enroll/reenroll request body.  The canonical
  //    client sends the PEM CSR verbatim in "certificate_request".
  json req;
  req["certificate_request"] = csrPEM;
  req["hosts"] = json::array({enrollmentId});
  if (profile.has_value()) {
    req["profile"] = profile.value();
  }
  if (attrReqs.has_value() && !attrReqs.value().empty()) {
    json attrReqJson;
    for (const auto &attr : attrReqs.value()) {
      attrReqJson.push_back({{"name", attr}, {"optional", false}});
    }
    req["attr_reqs"] = attrReqJson;
  }

  // 3. Submit over Basic auth.
  auto response = httpClient_->request(
      HttpMethod::POST, buildUrl(endpoint),
      authHeaders(enrollmentId, enrollmentSecret), req.dump(), 30);

  if (response.statusCode != 200 && response.statusCode != 201) {
    throw std::runtime_error(
        "CA enroll failed with status: " + std::to_string(response.statusCode) +
        ", body: " + extractServerError(response.body));
  }

  std::string certPEM = parseCertFromResponse(response.body);
  // Keep the private key in its self-wiping buffer all the way to the
  // Identity: returning it as a std::string here would leave a plaintext copy
  // that is never wiped.
  return {certPEM, std::move(privateKeyPEM)};
}

identity::Identity
CaClient::enroll(const std::string &enrollmentId,
                 const std::string &enrollmentSecret,
                 const std::optional<std::string> &profile,
                 const std::optional<std::vector<std::string>> &labels,
                 const std::optional<std::vector<std::string>> &attrReqs,
                 const std::optional<std::string> &type) {
  (void)labels; // fabric-ca enrollment has no "labels" field; kept for API
                // compat.
  (void)type;

  auto [certPEM, privateKeyPEM] = enrollCommon(
      enrollmentId, enrollmentSecret, "/api/v1/enroll", profile, attrReqs);
  return identity::Identity(mspId_, certPEM, privateKeyPEM);
}

CaClient::RegisterResponse CaClient::registerIdentity(
    const identity::Identity &registrar, const std::string &id,
    const std::optional<std::string> &type,
    const std::optional<int> &maxEnrollments,
    const std::optional<bool> &nodeRole, const std::optional<bool> &account,
    const std::optional<std::string> &affiliation,
    const std::optional<std::vector<std::string>> &attributes,
    const std::optional<std::string> &caName,
    const std::optional<std::string> &secret) {
  json req;
  req["id"] = id;
  if (type.has_value())
    req["type"] = type.value();
  if (maxEnrollments.has_value())
    req["max_enrollments"] = maxEnrollments.value();
  if (nodeRole.has_value())
    req["node_role"] = nodeRole.value();
  if (account.has_value())
    req["account"] = account.value();
  if (affiliation.has_value())
    req["affiliation"] = affiliation.value();
  if (attributes.has_value())
    req["attrs"] = attributes.value();
  if (caName.has_value())
    req["caname"] = caName.value();
  if (secret.has_value())
    req["secret"] = secret.value();

  const std::string body = req.dump();
  auto response = httpClient_->request(
      HttpMethod::POST, buildUrl("/api/v1/register"),
      tokenHeaders(registrar, "POST", "/api/v1/register", body), body, 30);

  if (response.statusCode != 200 && response.statusCode != 201) {
    throw std::runtime_error("CA register failed with status: " +
                             std::to_string(response.statusCode) +
                             ", body: " + extractServerError(response.body));
  }

  try {
    auto j = json::parse(response.body);
    RegisterResponse resp;
    // fabric-ca: {"result": {"secret": "...", ...}}
    if (j.contains("result") && j["result"].is_object()) {
      j = j["result"];
    }
    if (j.contains("secret") && j["secret"].is_string()) {
      resp.secret = j["secret"].get<std::string>();
    }
    if (j.contains("password") && j["password"].is_string()) {
      resp.password = j["password"].get<std::string>();
    }
    if (j.contains("enrollmentID") && j["enrollmentID"].is_string()) {
      resp.enrollmentID = j["enrollmentID"].get<std::string>();
    }
    if (j.contains("id") && j["id"].is_string()) {
      resp.enrollmentID = j["id"].get<std::string>();
    }
    if (j.contains("type") && j["type"].is_string()) {
      resp.type = j["type"].get<std::string>();
    }
    if (j.contains("affiliation") && j["affiliation"].is_string()) {
      resp.affiliation = j["affiliation"].get<std::string>();
    }
    if (j.contains("attributes") && j["attributes"].is_array()) {
      resp.attributes = j["attributes"].get<std::vector<std::string>>();
    }
    return resp;
  } catch (const json::exception &e) {
    throw std::runtime_error("Failed to parse CA register response: " +
                             std::string(e.what()));
  }
}

identity::Identity CaClient::reenroll(const identity::Identity &identity) {
  // Reenroll keeps the existing key material: build a fresh CSR from it and
  // authenticate with a token signed by the identity's current certificate.
  crypto::X509Certificate cert(identity.getCertificate());
  const std::string commonName = cert.getSubjectCommonName();
  const std::string csrPEM =
      crypto::CSR::generate(identity.getPrivateKey(), commonName);

  json req;
  req["certificate_request"] = csrPEM;
  req["hosts"] = json::array({commonName});

  const std::string body = req.dump();
  auto response = httpClient_->request(
      HttpMethod::POST, buildUrl("/api/v1/reenroll"),
      tokenHeaders(identity, "POST", "/api/v1/reenroll", body), body, 30);

  if (response.statusCode != 200 && response.statusCode != 201) {
    throw std::runtime_error("CA reenroll failed with status: " +
                             std::to_string(response.statusCode) +
                             ", body: " + extractServerError(response.body));
  }

  std::string certPEM = parseCertFromResponse(response.body);
  return identity::Identity(mspId_, certPEM, identity.getPrivateKey());
}

CaClient::RevokeResponse
CaClient::revoke(const identity::Identity &registrar, const std::string &name,
                 const std::optional<std::string> &aki,
                 const std::optional<std::string> &serial,
                 const std::optional<std::string> &reason,
                 const std::optional<bool> &genCRL) {
  json req;
  req["id"] = name;
  if (aki.has_value())
    req["aki"] = aki.value();
  if (serial.has_value())
    req["serial"] = serial.value();
  if (reason.has_value())
    req["reason"] = reason.value();
  if (genCRL.has_value())
    req["gencrl"] = genCRL.value();

  const std::string body = req.dump();
  auto response = httpClient_->request(
      HttpMethod::POST, buildUrl("/api/v1/revoke"),
      tokenHeaders(registrar, "POST", "/api/v1/revoke", body), body, 30);

  if (response.statusCode != 200 && response.statusCode != 201) {
    throw std::runtime_error(
        "CA revoke failed with status: " + std::to_string(response.statusCode) +
        ", body: " + extractServerError(response.body));
  }

  try {
    auto j = json::parse(response.body);
    RevokeResponse resp;
    // fabric-ca: {"result": {"CRL": "<base64>", "RevokedCerts": [...]}}
    if (j.contains("result") && j["result"].is_object()) {
      j = j["result"];
    }
    if (j.contains("CRL") && j["CRL"].is_string()) {
      resp.crl = decodePemField(j["CRL"]);
    }
    if (j.contains("RevokedCerts") && j["RevokedCerts"].is_array()) {
      json revoked = j["RevokedCerts"];
      if (revoked.is_array() && !revoked.empty()) {
        json joined = json::array();
        for (const auto &item : revoked) {
          if (item.is_object() && item.contains("Cert") &&
              item["Cert"].is_string()) {
            joined.push_back(item["Cert"]);
          } else if (item.is_string()) {
            joined.push_back(item);
          }
        }
        resp.revokedCertificates = joined.dump();
      }
    }
    return resp;
  } catch (const json::exception &e) {
    throw std::runtime_error("Failed to parse CA revoke response: " +
                             std::string(e.what()));
  }
}

CaClient::CaInfoResponse CaClient::getCAInfo() {
  auto response =
      httpClient_->request(HttpMethod::GET, buildUrl("/api/v1/cainfo"), {});

  if (response.statusCode != 200) {
    throw std::runtime_error(
        "CA info failed with status: " + std::to_string(response.statusCode) +
        ", body: " + extractServerError(response.body));
  }

  try {
    auto j = json::parse(response.body);
    CaInfoResponse resp;
    // fabric-ca: {"result": {"Version": "...", "CAName": "...", "CAChain":
    // "<base64>"}}
    if (j.contains("result") && j["result"].is_object()) {
      j = j["result"];
    }
    if (j.contains("Version") && j["Version"].is_string()) {
      resp.version = j["Version"].get<std::string>();
    }
    if (j.contains("CAName") && j["CAName"].is_string()) {
      resp.caName = j["CAName"].get<std::string>();
    }
    if (j.contains("CAChain") && j["CAChain"].is_string()) {
      resp.caChain = splitPemChain(decodePemField(j["CAChain"]));
    }
    if (j.contains("caChain") && j["caChain"].is_array()) {
      for (const auto &cert : j["caChain"]) {
        std::string pem = decodePemField(cert);
        if (!pem.empty())
          resp.caChain.push_back(pem);
      }
    }
    resp.caCerts = resp.caChain;
    return resp;
  } catch (const json::exception &e) {
    throw std::runtime_error("Failed to parse CA info response: " +
                             std::string(e.what()));
  }
}

std::vector<std::string> CaClient::getCertificates(
    const identity::Identity &registrar, const std::optional<std::string> &aki,
    const std::optional<std::string> &serial,
    const std::optional<std::string> &authorityKeyIdentifier) {
  // fabric-ca lists certificates via GET /api/v1/certificates, gated behind
  // registrar token authorization.  The token signs the byte-exact request
  // URI (path + query) with an empty body.
  const std::string path = "/api/v1/certificates";
  std::string query;
  bool first = true;
  auto appendQuery = [&](const std::string &key, const std::string &value) {
    query += (first ? "?" : "&");
    first = false;
    query += key + "=" + value;
  };
  if (aki.has_value())
    appendQuery("aki", aki.value());
  if (serial.has_value())
    appendQuery("serial", serial.value());
  if (authorityKeyIdentifier.has_value())
    appendQuery("authority_key_identifier", authorityKeyIdentifier.value());

  const std::string uri = path + query;
  auto response = httpClient_->request(HttpMethod::GET, buildUrl(uri),
                                       tokenHeaders(registrar, "GET", uri, ""));

  if (response.statusCode != 200) {
    throw std::runtime_error(
        "CA certs failed with status: " + std::to_string(response.statusCode) +
        ", body: " + extractServerError(response.body));
  }

  try {
    auto j = json::parse(response.body);
    if (j.contains("result") && j["result"].is_object()) {
      j = j["result"];
    }
    std::vector<std::string> certs;

    auto collect = [&certs](const json &node) {
      if (node.is_string()) {
        std::string pem = decodePemField(node);
        if (pem.find("BEGIN CERTIFICATE") != std::string::npos &&
            !pem.empty()) {
          certs.push_back(pem);
        }
        return;
      }
      // fabric-ca returns each cert as {"PEM": "<base64>"} (or "Cert").
      if (node.is_object()) {
        for (const auto &field : {"PEM", "Cert", "cert"}) {
          if (node.contains(field)) {
            std::string pem = decodePemField(node[field]);
            if (pem.find("BEGIN CERTIFICATE") != std::string::npos &&
                !pem.empty()) {
              certs.push_back(pem);
            }
            return;
          }
        }
      }
    };

    if (j.is_array()) {
      for (const auto &item : j)
        collect(item);
    } else {
      for (const auto &field :
           {"certs", "certificates", "Certificates", "result"}) {
        if (j.contains(field) && j[field].is_array()) {
          for (const auto &item : j[field])
            collect(item);
        }
      }
    }
    return certs;
  } catch (const json::exception &e) {
    throw std::runtime_error("Failed to parse CA certificates response: " +
                             std::string(e.what()));
  }
}

} // namespace ca
} // namespace fabric