// test_grpc.cpp — Phase 3 gRPC transport tests.
//
// GrpcConnection (mTLS credentials, hostname override, channel readiness) is
// exercised against a local in-process gRPC echo server, so the tests need no
// Fabric peer.  TLS material is generated on the fly with OpenSSL.

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <memory>
#include <string>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <grpcpp/grpcpp.h>
#include <grpcpp/security/server_credentials.h>

#include "fabric/grpc/grpc_connection.h"
#include "fabric/grpc/grpc_status.h"

#include "echo.grpc.pb.h"

using fabric::grpc::ChannelOptions;
using fabric::grpc::ConnectionError;
using fabric::grpc::GrpcConnection;
using fabric::grpc::StatusException;
using fabric::grpc::TlsCredentials;

namespace {

// ─────────────────────────────────────────────────────────────────────────────
// TLS fixture generation (P-256 ECDSA CA + server leaf with DNS SANs)
// ─────────────────────────────────────────────────────────────────────────────

struct PemBundle {
    std::string key;
    std::string cert;
};

EVP_PKEY* newEcKey() {
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec || EC_KEY_generate_key(ec) != 1) return nullptr;
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec);
    return pkey;
}

std::string pemKey(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string out(data, len);
    BIO_free(bio);
    return out;
}

std::string pemCert(X509* x) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, x);
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string out(data, len);
    BIO_free(bio);
    return out;
}

void addExtension(X509* x, X509* issuer, int nid, const char* value) {
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, issuer, x, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    if (ext) {
        X509_add_ext(x, ext, -1);
        X509_EXTENSION_free(ext);
    }
}

X509* makeCert(EVP_PKEY* subjectKey, X509* issuer, EVP_PKEY* issuerKey,
               bool isCa, const std::string& cn,
               const std::vector<std::string>& dnsSans) {
    X509* x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), -60);
    X509_gmtime_adj(X509_getm_notAfter(x), 24 * 3600);
    X509_set_pubkey(x, subjectKey);

    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn.c_str()),
                               -1, -1, 0);
    if (isCa) {
        X509_set_issuer_name(x, name);  // self-signed root
        addExtension(x, x, NID_basic_constraints, "critical,CA:TRUE");
        X509_sign(x, subjectKey, EVP_sha256());
    } else {
        X509_set_issuer_name(x, X509_get_subject_name(issuer));
        addExtension(x, issuer, NID_basic_constraints, "critical,CA:FALSE");
        addExtension(x, issuer, NID_key_usage, "critical,digitalSignature,keyEncipherment");
        addExtension(x, issuer, NID_ext_key_usage, "serverAuth");
        std::string san = "DNS:" + dnsSans[0];
        for (std::size_t i = 1; i < dnsSans.size(); ++i) san += ",DNS:" + dnsSans[i];
        addExtension(x, issuer, NID_subject_alt_name, san.c_str());
        X509_sign(x, issuerKey, EVP_sha256());
    }
    return x;
}

struct CertFixture {
    PemBundle ca;
    PemBundle leaf;
};

CertFixture makeCertFixture(const std::string& leafCn,
                            const std::vector<std::string>& dnsSans) {
    EVP_PKEY* caKey = newEcKey();
    X509* ca = makeCert(caKey, nullptr, nullptr, true, "test-ca", {});
    EVP_PKEY* leafKey = newEcKey();
    X509* leaf = makeCert(leafKey, ca, caKey, false, leafCn, dnsSans);

    CertFixture f;
    f.ca.key = pemKey(caKey);
    f.ca.cert = pemCert(ca);
    f.leaf.key = pemKey(leafKey);
    f.leaf.cert = pemCert(leaf);
    X509_free(ca);
    X509_free(leaf);
    return f;
}

// ─────────────────────────────────────────────────────────────────────────────
// Echo server
// ─────────────────────────────────────────────────────────────────────────────

class EchoServiceImpl final : public testecho::Echo::Service {
    grpc::Status Ping(grpc::ServerContext*, const testecho::PingRequest* req,
                      testecho::PingResponse* resp) override {
        if (req->fail_status() != 0) {
            return grpc::Status(static_cast<grpc::StatusCode>(req->fail_status()),
                                "injected failure");
        }
        resp->set_message(req->message());
        return grpc::Status::OK;
    }
};

std::string targetFor(int port) {
    return "localhost:" + std::to_string(port);
}

int freePort() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    socklen_t len = sizeof(addr);
    getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len);
    int port = ntohs(addr.sin_port);
    close(fd);
    return port;
}

// Runs a synchronous RPC through a channel, returning the gRPC status.
grpc::Status ping(const std::shared_ptr<grpc::Channel>& channel,
                  const std::string& message, int failStatus = 0) {
    testecho::Echo::Stub stub(channel);
    grpc::ClientContext ctx;
    testecho::PingRequest req;
    req.set_message(message);
    req.set_fail_status(failStatus);
    testecho::PingResponse resp;
    grpc::Status status = stub.Ping(&ctx, req, &resp);
    if (status.ok() && !resp.message().empty()) {
        EXPECT_EQ(resp.message(), message);
    }
    return status;
}

ChannelOptions testOptions(int waitMs = 3000) {
    ChannelOptions opts;
    opts.keepAliveTime = std::chrono::milliseconds(500);
    opts.keepAliveTimeout = std::chrono::milliseconds(300);
    opts.minReconnectBackoff = std::chrono::milliseconds(50);
    opts.maxReconnectBackoff = std::chrono::milliseconds(200);
    opts.waitForReadyTimeout = std::chrono::milliseconds(waitMs);
    return opts;
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Status mapping
// ─────────────────────────────────────────────────────────────────────────────

TEST(GrpcStatusTest, StatusCodeName_AllCodes) {
    EXPECT_STREQ(fabric::grpc::statusCodeName(grpc::StatusCode::OK), "OK");
    EXPECT_STREQ(fabric::grpc::statusCodeName(grpc::StatusCode::NOT_FOUND), "NOT_FOUND");
    EXPECT_STREQ(fabric::grpc::statusCodeName(grpc::StatusCode::UNAVAILABLE), "UNAVAILABLE");
    EXPECT_STREQ(fabric::grpc::statusCodeName(grpc::StatusCode::PERMISSION_DENIED), "PERMISSION_DENIED");
}

TEST(GrpcStatusTest, IsRetryable_DistinguishesTransientFromPermanent) {
    EXPECT_TRUE(fabric::grpc::isRetryable(grpc::StatusCode::UNAVAILABLE));
    EXPECT_TRUE(fabric::grpc::isRetryable(grpc::StatusCode::DEADLINE_EXCEEDED));
    EXPECT_TRUE(fabric::grpc::isRetryable(grpc::StatusCode::ABORTED));
    EXPECT_FALSE(fabric::grpc::isRetryable(grpc::StatusCode::NOT_FOUND));
    EXPECT_FALSE(fabric::grpc::isRetryable(grpc::StatusCode::INVALID_ARGUMENT));
    EXPECT_FALSE(fabric::grpc::isRetryable(grpc::StatusCode::PERMISSION_DENIED));
}

TEST(GrpcStatusTest, StatusException_CarriesCodeAndMessage) {
    StatusException exc(grpc::StatusCode::NOT_FOUND, "no such chaincode", "extra detail");
    EXPECT_EQ(exc.code(), grpc::StatusCode::NOT_FOUND);
    EXPECT_EQ(exc.grpcMessage(), "no such chaincode");
    EXPECT_EQ(exc.details(), "extra detail");
    std::string what = exc.what();
    EXPECT_TRUE(what.find("(NOT_FOUND): no such chaincode") != std::string::npos);
    EXPECT_TRUE(what.find("extra detail") != std::string::npos);
}

// ─────────────────────────────────────────────────────────────────────────────
// GrpcConnection over insecure transport
// ─────────────────────────────────────────────────────────────────────────────

class InsecureConnectionTest : public ::testing::Test {
protected:
    void SetUp() override {
        port_ = freePort();
        ASSERT_GT(port_, 0);
        builder_.AddListeningPort(targetFor(port_), grpc::InsecureServerCredentials());
        builder_.RegisterService(&echo_);
        server_ = builder_.BuildAndStart();
        ASSERT_NE(server_, nullptr);
    }

    void TearDown() override {
        if (server_) server_->Shutdown();
    }

    int port_ = 0;
    EchoServiceImpl echo_;
    grpc::ServerBuilder builder_;
    std::unique_ptr<grpc::Server> server_;
};

TEST_F(InsecureConnectionTest, RoundTrip) {
    auto conn = GrpcConnection::connectInsecure(targetFor(port_), testOptions());
    conn->waitForReady();
    EXPECT_TRUE(conn->isReady());

    grpc::Status status = ping(conn->channel(), "hello grpc");
    EXPECT_TRUE(status.ok());
}

TEST_F(InsecureConnectionTest, ServerRejectionSurfacesAsStatusException) {
    auto conn = GrpcConnection::connectInsecure(targetFor(port_), testOptions());
    conn->waitForReady();

    auto stub = testecho::Echo::NewStub(conn->channel());
    grpc::ClientContext ctx;
    testecho::PingRequest req;
    req.set_fail_status(static_cast<int>(grpc::StatusCode::NOT_FOUND));
    testecho::PingResponse resp;
    grpc::Status status = stub->Ping(&ctx, req, &resp);

    EXPECT_EQ(status.error_code(), grpc::StatusCode::NOT_FOUND);
    EXPECT_TRUE(std::string(status.error_message()).find("injected failure") != std::string::npos);

    // The SDK maps non-OK statuses to StatusException.
    StatusException exc(status.error_code(), status.error_message(), std::string(status.error_details()));
    EXPECT_EQ(exc.code(), grpc::StatusCode::NOT_FOUND);
}

TEST_F(InsecureConnectionTest, UnreachableTargetTimesOutReady) {
    ChannelOptions opts = testOptions(1500);
    auto conn = GrpcConnection::connectInsecure(targetFor(freePort()), opts);
    EXPECT_THROW(conn->waitForReady(), ConnectionError);
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS transport
// ─────────────────────────────────────────────────────────────────────────────

class TlsConnectionTest : public ::testing::Test {
protected:
    void startTlsServer(const CertFixture& fixture) {
        grpc::SslServerCredentialsOptions sslOpts;
        sslOpts.pem_key_cert_pairs.push_back(
            grpc::SslServerCredentialsOptions::PemKeyCertPair{ fixture.leaf.key, fixture.leaf.cert });
        port_ = freePort();
        ASSERT_GT(port_, 0);
        serverBuilder_.AddListeningPort(targetFor(port_), grpc::SslServerCredentials(sslOpts));
        serverBuilder_.RegisterService(&echo_);
        server_ = serverBuilder_.BuildAndStart();
        ASSERT_NE(server_, nullptr);
    }

    void TearDown() override {
        if (server_) server_->Shutdown();
    }

    int port_ = 0;
    EchoServiceImpl echo_;
    grpc::ServerBuilder serverBuilder_;
    std::unique_ptr<grpc::Server> server_;
};

TEST_F(TlsConnectionTest, TrustedCaRoundTrip) {
    CertFixture fx = makeCertFixture("localhost", { "localhost" });
    startTlsServer(fx);

    TlsCredentials creds;
    creds.rootCert = fx.ca.cert;
    auto conn = GrpcConnection::connect(targetFor(port_), creds, testOptions(5000));
    conn->waitForReady();
    EXPECT_TRUE(conn->isReady());

    EXPECT_TRUE(ping(conn->channel(), "tls hello").ok());
}

TEST_F(TlsConnectionTest, UntrustedCaIsRejected) {
    CertFixture serverFx = makeCertFixture("localhost", { "localhost" });
    startTlsServer(serverFx);

    CertFixture otherCa = makeCertFixture("wrong", { "wrong.example" });
    TlsCredentials creds;
    creds.rootCert = otherCa.ca.cert;  // not the CA that signed the server cert

    auto conn = GrpcConnection::connect(targetFor(port_), creds, testOptions(2000));
    // The TLS handshake cannot complete, so the channel never becomes ready.
    EXPECT_THROW(conn->waitForReady(), ConnectionError);
}

TEST_F(TlsConnectionTest, ServerNameOverrideAcceptsMismatchedCert) {
    CertFixture fx = makeCertFixture("private.example", { "private.example" });
    startTlsServer(fx);

    // Target host (localhost) does not match the cert SAN; the override makes
    // gRPC verify against "private.example" instead.
    TlsCredentials creds;
    creds.rootCert = fx.ca.cert;
    creds.serverNameOverride = "private.example";
    auto conn = GrpcConnection::connect(targetFor(port_), creds, testOptions(5000));
    conn->waitForReady();

    EXPECT_TRUE(ping(conn->channel(), "override hello").ok());
}

TEST_F(TlsConnectionTest, WithoutOverrideHostnameMismatchFails) {
    CertFixture fx = makeCertFixture("private.example", { "private.example" });
    startTlsServer(fx);

    TlsCredentials creds;
    creds.rootCert = fx.ca.cert;  // trusted CA but hostname mismatch
    auto conn = GrpcConnection::connect(targetFor(port_), creds, testOptions(2000));

    EXPECT_THROW(conn->waitForReady(), ConnectionError);
}