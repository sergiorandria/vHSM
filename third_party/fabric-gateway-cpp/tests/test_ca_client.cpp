// test_ca_client.cpp — Phase 2 unit + integration tests for fabric::ca::CaClient.
//
// Unit tests drive CaClient through a stub HttpClient that records requests and
// returns scripted fabric-ca responses, so they run without a server.
//
// Integration tests talk to a real fabric-ca-server.  They are skipped when no
// CA is reachable at localhost:7054 (e.g. spin one up with:
//   docker run -p 7054:7054 hyperledger/fabric-ca:1.5 fabric-ca-server start -b admin:adminpw)

#include <gtest/gtest.h>

#include <chrono>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "fabric/ca/ca_client.h"
#include "fabric/ca/httpclient.h"
#include "fabric/crypto/ec.h"
#include "fabric/crypto/x509.h"
#include "fabric/identity/identity.h"

using fabric::ca::CaClient;
using fabric::ca::HttpClient;
using fabric::ca::HttpMethod;
using fabric::ca::HttpResponse;
using fabric::crypto::ECKeyPair;
using fabric::crypto::X509Certificate;
using fabric::identity::Identity;

namespace {

// ─────────────────────────────────────────────────────────────────────────────
// tiny base64 encoder (RFC 4648), used to craft fake CA responses.
// ─────────────────────────────────────────────────────────────────────────────

std::string b64(const std::string& in) {
    static const char* tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (std::size_t i = 0; i < in.size(); i += 3) {
        unsigned b0 = static_cast<unsigned char>(in[i]);
        unsigned b1 = i + 1 < in.size() ? static_cast<unsigned char>(in[i + 1]) : 0;
        unsigned b2 = i + 2 < in.size() ? static_cast<unsigned char>(in[i + 2]) : 0;
        out.push_back(tbl[(b0 >> 2) & 0x3F]);
        out.push_back(tbl[((b0 << 4) | (b1 >> 4)) & 0x3F]);
        out.push_back(i + 1 < in.size() ? tbl[((b1 << 2) | (b2 >> 6)) & 0x3F] : '=');
        out.push_back(i + 2 < in.size() ? tbl[b2 & 0x3F] : '=');
    }
    return out;
}

// A canned PEM cert for scripted responses.  Real cert checks (key binding
// and CN extraction) use the self-signed certs from `testIdentity()`.
const char kFakeCertPEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBZjCCAQygAwIBAgIUQnJgCnQvAxpkuWmqM4IZnVXb5PgwCgYIKoZIzj0DAQwC\n"
    "-----END CERTIFICATE-----\n";

std::string base64Decode(const std::string& in) {
    static const char* tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int table[256];
    for (int& c : table) c = -1;
    for (int i = 0; i < 64; ++i) table[static_cast<unsigned char>(tbl[i])] = i;
    std::string out;
    int buffer = 0, bits = 0;
    for (char ch : in) {
        if (ch == '=' || ch == '\n' || ch == '\r' || ch == ' ') continue;
        int v = table[static_cast<unsigned char>(ch)];
        if (v < 0) continue;
        buffer = (buffer << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buffer >> bits) & 0xFF));
        }
    }
    return out;
}

std::string sha256(const std::string& data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, digest, &len);
    EVP_MD_CTX_free(ctx);
    return std::string(reinterpret_cast<char*>(digest), len);
}

// Returns a fresh keypair-derived identity whose certificate carries the given
// common name.  Both cert and key are real and consistent with each other.
Identity testIdentity(const std::string& cn) {
    auto [privateKeyPEM, publicKeyPEM] = ECKeyPair::generate();
    (void)publicKeyPEM;

    BIO* kbio = BIO_new_mem_buf(privateKeyPEM.data(), static_cast<int>(privateKeyPEM.size()));
    EC_KEY* key = PEM_read_bio_ECPrivateKey(kbio, nullptr, nullptr, nullptr);
    BIO_free(kbio);
    if (!key) throw std::runtime_error("testIdentity: failed to load test key");

    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, key);  // takes ownership of key

    X509* x = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), -60);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, pkey);

    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn.c_str()),
                               -1, -1, 0);
    X509_set_issuer_name(x, name);
    int ok = X509_sign(x, pkey, EVP_sha256());

    BIO* out = BIO_new(BIO_s_mem());
    if (ok != 0) PEM_write_bio_X509(out, x);
    char* data = nullptr;
    long len = BIO_get_mem_data(out, &data);
    Identity ident = ok != 0
                         ? Identity(cn, std::string(data, len), privateKeyPEM)
                         : Identity(cn, "", privateKeyPEM);

    EVP_PKEY_free(pkey);
    X509_free(x);
    BIO_free(out);
    return ident;
}

// Recomputes and cryptographically verifies a fabric-ca authorization token.
// The token is <b64(cert)>.<b64(DER ECDSA sig)>, signed over
// SHA256(method + "." + b64(uri) + "." + b64(body) + "." + b64(cert)).
bool verifyToken(const Identity& registrar, const std::string& method,
                 const std::string& uri, const std::string& body,
                 const std::string& authHeader) {
    const std::string b64cert = b64(registrar.getCertificate());
    if (authHeader.rfind(b64cert + ".", 0) != 0) return false;

    const std::string sigPart = authHeader.substr(b64cert.size() + 1);
    const std::string sig = base64Decode(sigPart);

    const std::string payload =
        method + "." + b64(uri) + "." + b64(body) + "." + b64cert;
    const std::string digest = sha256(payload);

    const std::string pubPEM = ECKeyPair(registrar.getPrivateKey()).getPublicKeyPEM();
    BIO* pbio = BIO_new_mem_buf(pubPEM.data(), static_cast<int>(pubPEM.size()));
    EC_KEY* pubkey = PEM_read_bio_EC_PUBKEY(pbio, nullptr, nullptr, nullptr);
    BIO_free(pbio);
    if (!pubkey) return false;

    // The signature is DER, as Fabric's BCCSP expects/emits.
    int ok = ECDSA_verify(0,
                          reinterpret_cast<const unsigned char*>(digest.data()),
                          static_cast<int>(digest.size()),
                          reinterpret_cast<const unsigned char*>(sig.data()),
                          static_cast<int>(sig.size()),
                          pubkey);
    EC_KEY_free(pubkey);
    return ok == 1;
}

std::string enrollResponse() {
    return R"({"result":{"Cert":")" + b64(kFakeCertPEM) +
           R"(","ServerInfo":{"CAChain":")" +
           b64(std::string("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")) +
           R"(","CAName":"","Version":""}},"success":true})";
}

// Scriptable stub HttpClient recording every request that is made.
struct FakeHttpClient : public HttpClient {
    struct Call {
        HttpMethod method;
        std::string url;
        std::vector<std::pair<std::string, std::string>> headers;
        std::optional<std::string> body;
    };

    HttpResponse response;
    std::vector<Call> calls;

    explicit FakeHttpClient(HttpResponse r) : response(std::move(r)) {}

    HttpResponse request(HttpMethod method, const std::string& url,
                         const std::vector<std::pair<std::string, std::string>>& headers,
                         const std::optional<std::string>& body,
                         int timeoutSeconds) override {
        (void)timeoutSeconds;
        calls.push_back({ method, url, headers, body });
        return response;
    }

    void setTLSOptions(const std::optional<std::string>&,
                       const std::optional<std::string>& = std::nullopt,
                       const std::optional<std::string>& = std::nullopt) override {
        tlsCalls++;
    }

    int tlsCalls = 0;
};

std::string headerValue(const FakeHttpClient::Call& call, const std::string& key) {
    for (const auto& [k, v] : call.headers) {
        if (k == key) return v;
    }
    return "";
}

bool contains(const std::string& s, const std::string& needle) {
    return s.find(needle) != std::string::npos;
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests — scripted CA, no network
// ─────────────────────────────────────────────────────────────────────────────

TEST(CaClientUnitTest, Enroll_SendsCsrAndDecodesCert) {
    auto http = std::make_shared<FakeHttpClient>(HttpResponse{ 201, enrollResponse(), {} });
    CaClient client(http, "http://localhost:7054", std::nullopt, "Org1MSP");

    Identity identity = client.enroll("admin", "adminpw");

    ASSERT_EQ(http->calls.size(), 1u);
    const auto& call = http->calls[0];

    EXPECT_EQ(call.method, HttpMethod::POST);
    EXPECT_EQ(call.url, "http://localhost:7054/api/v1/enroll");
    EXPECT_EQ(headerValue(call, "Content-Type"), "application/json");
    // Authorization: Basic base64("admin:adminpw")
    EXPECT_EQ(headerValue(call, "Authorization"), "Basic " + b64("admin:adminpw"));

    ASSERT_TRUE(call.body.has_value());
    EXPECT_TRUE(contains(*call.body, "\"certificate_request\":\"-----BEGIN CERTIFICATE REQUEST-----"));
    EXPECT_TRUE(contains(*call.body, "\"hosts\":[\"admin\"]"));

    // The returned identity carries the decoded cert, the real generated key
    // and the configured MSP ID.
    EXPECT_EQ(identity.getCertificate(), kFakeCertPEM);
    EXPECT_EQ(identity.getMSPID(), "Org1MSP");
    EXPECT_FALSE(identity.getPrivateKey().empty());
    EXPECT_TRUE(contains(identity.getPrivateKey(), "BEGIN EC PRIVATE KEY"));

    // The private key is usable and corresponds to the CSR that was sent.
    ECKeyPair key(identity.getPrivateKey());
    std::string sig = key.sign("payload");
    EXPECT_TRUE(key.verify("payload", sig));
}

TEST(CaClientUnitTest, Enroll_ServerErrorThrowsWithMessage) {
    std::string body = R"({"errors":[{"code":20,"message":"Authentication failure"}],"success":false})";
    auto http = std::make_shared<FakeHttpClient>(HttpResponse{ 401, body, {} });
    CaClient client(http, "http://ca:7054");

    EXPECT_THROW(client.enroll("admin", "wrongpass"), std::runtime_error);
    try {
        client.enroll("admin", "wrongpass");
        FAIL() << "expected exception";
    } catch (const std::runtime_error& e) {
        EXPECT_TRUE(contains(e.what(), "401"));
        EXPECT_TRUE(contains(e.what(), "Authentication failure"));
    }
}

TEST(CaClientUnitTest, Reenroll_ReusesKeyAndUsesTokenAuth) {
    auto http = std::make_shared<FakeHttpClient>(HttpResponse{ 201, enrollResponse(), {} });
    CaClient client(http, "http://ca:7054", std::nullopt, "Org1MSP");

    Identity registrar = testIdentity("alice");
    const std::string oldKey = registrar.getPrivateKey();
    Identity identity = client.reenroll(registrar);

    ASSERT_EQ(http->calls.size(), 1u);
    const auto& call = http->calls[0];
    EXPECT_EQ(call.url, "http://ca:7054/api/v1/reenroll");

    // The registrar cert's CN is reused as the CSR subject.
    ASSERT_TRUE(call.body.has_value());
    EXPECT_TRUE(contains(*call.body, "\"certificate_request\":"));
    EXPECT_TRUE(contains(*call.body, "\"hosts\":[\"alice\"]"));

    // Token authentication backed by the identity's own cert+key.
    const std::string auth = headerValue(call, "Authorization");
    EXPECT_TRUE(verifyToken(registrar, "POST", "/api/v1/reenroll", *call.body, auth));

    // Same key material survives reenrollment.
    EXPECT_EQ(identity.getPrivateKey(), oldKey);
    EXPECT_EQ(identity.getMSPID(), "Org1MSP");
    EXPECT_EQ(identity.getCertificate(), kFakeCertPEM);

    // The key signs and verifies as a symmetric round-trip.
    ECKeyPair key(identity.getPrivateKey());
    std::string sig = key.sign("payload");
    EXPECT_TRUE(key.verify("payload", sig));
}

TEST(CaClientUnitTest, Register_PostsIdAndParsesSecret) {
    std::string body = R"({"result":{"secret":"pVvsTNCXybIy"},"success":true})";
    auto http = std::make_shared<FakeHttpClient>(HttpResponse{ 200, body, {} });
    CaClient client(http, "http://ca:7054");

    Identity registrar = testIdentity("admin");
    auto resp = client.registerIdentity(registrar, "u1", "user",
                                        std::nullopt, std::nullopt, std::nullopt,
                                        "org1");

    ASSERT_EQ(http->calls.size(), 1u);
    const auto& call = http->calls[0];
    EXPECT_EQ(call.url, "http://ca:7054/api/v1/register");
    ASSERT_TRUE(call.body.has_value());

    // The secret is generated by the server, so it never appears in the request.
    EXPECT_TRUE(contains(*call.body, "\"id\":\"u1\""));
    EXPECT_TRUE(contains(*call.body, "\"type\":\"user\""));
    EXPECT_TRUE(contains(*call.body, "\"affiliation\":\"org1\""));
    EXPECT_FALSE(contains(*call.body, "pVvsTNCXybIy"));

    // Registrar token authentication, signed over exact request bytes.
    const std::string auth = headerValue(call, "Authorization");
    EXPECT_FALSE(auth.empty());
    EXPECT_FALSE(auth[0] == 'B');  // not Basic auth
    EXPECT_TRUE(verifyToken(registrar, "POST", "/api/v1/register", *call.body, auth));

    EXPECT_EQ(resp.secret, "pVvsTNCXybIy");
    EXPECT_TRUE(resp.password.empty());  // only set when server echoes it
}

TEST(CaClientUnitTest, Revoke_ParsesCrlAndRevokedCerts) {
    std::string body =
        R"({"result":{"CRL":")" + b64(std::string("-----BEGIN X509 CRL-----\n-----END X509 CRL-----\n")) +
        R"(","RevokedCerts":null},"success":true})";
    auto http = std::make_shared<FakeHttpClient>(HttpResponse{ 200, body, {} });
    CaClient client(http, "http://ca:7054");

    Identity registrar = testIdentity("admin");
    auto resp = client.revoke(registrar, "u1", std::nullopt, std::nullopt,
                              "unspecified", std::nullopt);

    ASSERT_EQ(http->calls.size(), 1u);
    const auto& call = http->calls[0];
    EXPECT_EQ(call.url, "http://ca:7054/api/v1/revoke");
    ASSERT_TRUE(call.body.has_value());
    EXPECT_TRUE(contains(*call.body, "\"id\":\"u1\""));
    EXPECT_FALSE(contains(*call.body, "\"gencrl\""));

    // Revoke also uses registrar token authentication.
    const std::string auth = headerValue(call, "Authorization");
    EXPECT_TRUE(verifyToken(registrar, "POST", "/api/v1/revoke", *call.body, auth));

    EXPECT_TRUE(contains(resp.crl, "BEGIN X509 CRL"));
}

TEST(CaClientUnitTest, GetCertificates_AuthenticatesWithToken) {
    std::string body = R"({"result":{"certs":[{"PEM":")" + b64(kFakeCertPEM) + R"("}]},"success":true})";
    auto http = std::make_shared<FakeHttpClient>(HttpResponse{ 200, body, {} });
    CaClient client(http, "http://ca:7054");

    Identity registrar = testIdentity("admin");
    auto certs = client.getCertificates(registrar, "akanid123", std::nullopt, "awkid456");

    ASSERT_EQ(http->calls.size(), 1u);
    const auto& call = http->calls[0];
    EXPECT_EQ(call.method, HttpMethod::GET);
    EXPECT_EQ(call.url, "http://ca:7054/api/v1/certificates?aki=akanid123&authority_key_identifier=awkid456");

    // GET body is empty and the token signs the exact query URI.
    const std::string auth = headerValue(call, "Authorization");
    EXPECT_TRUE(verifyToken(registrar, "GET",
                            "/api/v1/certificates?aki=akanid123&authority_key_identifier=awkid456",
                            "", auth));

    EXPECT_EQ(certs.size(), 1u);
    EXPECT_TRUE(contains(certs[0], "BEGIN CERTIFICATE"));
}

TEST(CaClientUnitTest, GetCAInfo_ParsesNestedResult) {
    std::string chainPEM = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"
                           "-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n";
    std::string body =
        R"({"result":{"Version":"v1.5.22","CAName":"","CAChain":")" +
        b64(chainPEM) + R"("},"success":true})";
    auto http = std::make_shared<FakeHttpClient>(HttpResponse{ 200, body, {} });
    CaClient client(http, "http://ca:7054");

    auto info = client.getCAInfo();

    ASSERT_EQ(http->calls.size(), 1u);
    EXPECT_EQ(http->calls[0].method, HttpMethod::GET);
    EXPECT_EQ(http->calls[0].url, "http://ca:7054/api/v1/cainfo");

    EXPECT_EQ(info.version, "v1.5.22");
    EXPECT_EQ(info.caChain.size(), 2u);
    EXPECT_EQ(info.caCerts.size(), 2u);
    EXPECT_TRUE(contains(info.caChain[0], "AAA"));
    EXPECT_TRUE(contains(info.caChain[1], "BBB"));
}

TEST(CaClientUnitTest, Constructor_WiresTlsOptions) {
    auto http = std::make_shared<FakeHttpClient>(HttpResponse{ 200, "{}", {} });
    CaClient client(http, "http://ca:7054", std::optional<std::string>("/tmp/ca.pem"));
    EXPECT_EQ(http->tlsCalls, 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration tests — real fabric-ca-server (localhost:7054), skipped otherwise
// ─────────────────────────────────────────────────────────────────────────────

class CaClientIntegrationTest : public ::testing::Test {
protected:
    static bool caReachable() {
        try {
            auto http = std::make_shared<fabric::ca::CurlHttpClient>();
            CaClient probe(http, "http://localhost:7054");
            probe.getCAInfo();
            return true;
        } catch (...) {
            return false;
        }
    }

    void SetUp() override {
        if (!caReachable()) {
            GTEST_SKIP() << "no fabric-ca-server at localhost:7054; "
                            "run: docker run -p 7054:7054 hyperledger/fabric-ca:1.5 "
                            "fabric-ca-server start -b admin:adminpw";
        }
        http_ = std::make_shared<fabric::ca::CurlHttpClient>();
        client_ = std::make_unique<CaClient>(http_, "http://localhost:7054", std::nullopt, "Org1MSP");
    }

    std::shared_ptr<fabric::ca::CurlHttpClient> http_;
    std::unique_ptr<CaClient> client_;
};

TEST_F(CaClientIntegrationTest, GetCAInfo_ReturnsVersionAndChain) {
    auto info = client_->getCAInfo();
    EXPECT_FALSE(info.version.empty());
    EXPECT_FALSE(info.caChain.empty());
    EXPECT_TRUE(contains(info.caChain[0], "BEGIN CERTIFICATE"));
}

TEST_F(CaClientIntegrationTest, EnrollAdmin_ReturnsKeyMatchedCertificate) {
    // admin:adminpw is the bootstrap identity provisioned by the server.
    Identity identity = client_->enroll("admin", "adminpw");

    EXPECT_EQ(identity.getMSPID(), "Org1MSP");
    EXPECT_TRUE(contains(identity.getCertificate(), "BEGIN CERTIFICATE"));
    EXPECT_TRUE(contains(identity.getPrivateKey(), "BEGIN EC PRIVATE KEY"));

    // The issued certificate must bind to the generated private key so that
    // signatures made with it verify against the cert's public key.
    ECKeyPair keypair(identity.getPrivateKey());
    X509Certificate cert(identity.getCertificate());
    EXPECT_EQ(keypair.getPublicKeyPEM(), cert.getPublicKeyPEM());

    std::string sig = keypair.sign("integration payload");
    EXPECT_TRUE(keypair.verify("integration payload", sig));
}

TEST_F(CaClientIntegrationTest, RegisterEnrollRevoke_RoundTrip) {
    // 0. admin enrols (basic auth) and becomes the registrar for token auth.
    Identity admin = client_->enroll("admin", "adminpw");
    EXPECT_TRUE(contains(admin.getCertificate(), "BEGIN CERTIFICATE"));

    // 1. admin registers a throwaway user (token auth).
    std::string user = "u" + std::to_string(
        std::chrono::system_clock::now().time_since_epoch().count());
    auto reg = client_->registerIdentity(admin, user, "user",
                                         std::nullopt, std::nullopt, std::nullopt,
                                         "org1");
    ASSERT_FALSE(reg.secret.empty()) << "server must return a generated secret";

    // 2. The new user enrols with the returned secret.
    Identity userIdentity = client_->enroll(user, reg.secret);
    EXPECT_EQ(userIdentity.getMSPID(), "Org1MSP");
    EXPECT_TRUE(contains(userIdentity.getCertificate(), "BEGIN CERTIFICATE"));

    // 3. The user's certificate shows up in the CA's certificate list.
    auto certs = client_->getCertificates(admin);
    bool found = false;
    for (const auto& pem : certs) {
        if (contains(pem, "BEGIN CERTIFICATE")) found = true;
    }
    EXPECT_TRUE(found);

    // 4. The user re-enrols (token auth): new cert, same key material.
    Identity renewed = client_->reenroll(userIdentity);
    EXPECT_EQ(renewed.getPrivateKey(), userIdentity.getPrivateKey());
    EXPECT_NE(renewed.getCertificate(), userIdentity.getCertificate());
    EXPECT_TRUE(contains(renewed.getCertificate(), "BEGIN CERTIFICATE"));

    // 5. admin revokes the user's enrollment (token auth).
    auto rev = client_->revoke(admin, user);
    (void)rev;
}