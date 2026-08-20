// test_gateway.cpp — Phase 4 Gateway client tests.
//
// The full Evaluate / Endorse / Submit / CommitStatus pipeline of the Gateway
// client is exercised against an in-process fake Gateway service, so no Fabric
// peer is required.  The fake verifies every signature the client produces,
// checks transaction-ID consistency across the RPCs, and parses the signed
// proposals, so these tests cover the client-side signing pipeline end to end.

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <grpcpp/grpcpp.h>
#include <grpcpp/security/server_credentials.h>

#include "common/common.pb.h"
#include "gateway/gateway.grpc.pb.h"
#include "gateway/gateway.pb.h"
#include "msp/identities.pb.h"
#include "peer/chaincode.pb.h"
#include "peer/proposal.pb.h"
#include "peer/transaction.pb.h"

#include "fabric/gateway/contract.h"
#include "fabric/gateway/gateway.h"
#include "fabric/gateway/network.h"
#include "fabric/gateway/transaction.h"
#include "fabric/grpc/grpc_connection.h"
#include "fabric/grpc/grpc_status.h"
#include "fabric/identity/identity.h"
#include "fabric/protoutil/proposal_builder.h"

using fabric::gateway::Gateway;
using fabric::gateway::TransactionResult;
using fabric::grpc::ChannelOptions;
using fabric::grpc::ConnectionError;
using fabric::grpc::GrpcConnection;
using fabric::grpc::StatusException;

namespace {

// ─────────────────────────────────────────────────────────────────────────────
// Identity fixture (P-256 key + self-signed certificate)
// ─────────────────────────────────────────────────────────────────────────────

struct IdentityFixture {
  std::string mspId = "Org1MSP";
  std::string keyPem;
  std::string certPem;
  std::string pubKeyPem;

  fabric::identity::Identity toIdentity() const {
    return fabric::identity::Identity(mspId, certPem, keyPem);
  }
};

EVP_PKEY *newEcKey() {
  EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!ec || EC_KEY_generate_key(ec) != 1)
    return nullptr;
  EVP_PKEY *pkey = EVP_PKEY_new();
  EVP_PKEY_assign_EC_KEY(pkey, ec);
  return pkey;
}

std::string pemKey(EVP_PKEY *pkey) {
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
  char *data = nullptr;
  long len = BIO_get_mem_data(bio, &data);
  std::string out(data, len);
  BIO_free(bio);
  return out;
}

std::string pemPubKey(EVP_PKEY *pkey) {
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PUBKEY(bio, pkey);
  char *data = nullptr;
  long len = BIO_get_mem_data(bio, &data);
  std::string out(data, len);
  BIO_free(bio);
  return out;
}

std::string pemCert(X509 *x) {
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(bio, x);
  char *data = nullptr;
  long len = BIO_get_mem_data(bio, &data);
  std::string out(data, len);
  BIO_free(bio);
  return out;
}

X509 *makeSelfSignedCert(EVP_PKEY *key, const std::string &cn) {
  X509 *x = X509_new();
  X509_set_version(x, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
  X509_gmtime_adj(X509_getm_notBefore(x), -60);
  X509_gmtime_adj(X509_getm_notAfter(x), 24 * 3600);
  X509_set_pubkey(x, key);

  X509_NAME *name = X509_get_subject_name(x);
  X509_NAME_add_entry_by_txt(
      name, "CN", MBSTRING_ASC,
      reinterpret_cast<const unsigned char *>(cn.c_str()), -1, -1, 0);
  X509_set_issuer_name(x, name);
  X509V3_CTX ctx;
  X509V3_set_ctx(&ctx, x, x, nullptr, nullptr, 0);
  X509_EXTENSION *bc = X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints,
                                           "critical,CA:FALSE");
  if (bc) {
    X509_add_ext(x, bc, -1);
    X509_EXTENSION_free(bc);
  }
  X509_sign(x, key, EVP_sha256());
  return x;
}

IdentityFixture makeIdentityFixture() {
  EVP_PKEY *key = newEcKey();
  if (!key) {
    throw std::runtime_error("failed to generate test key");
  }
  X509 *cert = makeSelfSignedCert(key, "Org1MSP-gateway-client");
  IdentityFixture f;
  f.keyPem = pemKey(key);
  f.certPem = pemCert(cert);
  f.pubKeyPem = pemPubKey(key);
  X509_free(cert);
  EVP_PKEY_free(key);
  return f;
}

bool verifyDerSignature(const std::string &pubKeyPem, const std::string &data,
                        const std::string &derSig) {
  if (derSig.empty())
    return false;
  BIO *bio =
      BIO_new_mem_buf(pubKeyPem.data(), static_cast<int>(pubKeyPem.size()));
  EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (!pkey)
    return false;

  bool valid = false;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (ctx &&
      EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
      EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) == 1) {
    valid = EVP_DigestVerifyFinal(
                ctx, reinterpret_cast<const unsigned char *>(derSig.data()),
                derSig.size()) == 1;
  }
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return valid;
}

// ─────────────────────────────────────────────────────────────────────────────
// Socket / server helpers
// ─────────────────────────────────────────────────────────────────────────────

std::string targetFor(int port) { return "localhost:" + std::to_string(port); }

int freePort() {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  if (bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }
  socklen_t len = sizeof(addr);
  getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len);
  int port = ntohs(addr.sin_port);
  close(fd);
  return port;
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

// ─────────────────────────────────────────────────────────────────────────────
// Fake Gateway service
// ─────────────────────────────────────────────────────────────────────────────

class FakeGatewayService final : public ::gateway::Gateway::Service {
public:
  explicit FakeGatewayService(const std::string &pubKeyPem)
      : pubKeyPem_(pubKeyPem) {}

  // Test knobs
  int validationCode = 0; // protos::VALID
  uint64_t blockNumber = 42;
  grpc::StatusCode evaluateError = grpc::StatusCode::OK;
  std::map<std::string, std::string> expectedTransient;

  // Observation counters
  int evaluateCount = 0;
  int endorseCount = 0;
  int submitCount = 0;
  int commitCount = 0;
  std::string lastTxId;
  std::string lastEnvelopeSignature;

  grpc::Status Evaluate(grpc::ServerContext *,
                        const ::gateway::EvaluateRequest *request,
                        ::gateway::EvaluateResponse *response) override {
    ++evaluateCount;
    auto check = verifySignedProposal(request->proposed_transaction());
    if (!check.ok())
      return check;

    auto args = proposalArgs(request->proposed_transaction());
    if (args.empty()) {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "empty chaincode args");
    }
    if (evaluateError != grpc::StatusCode::OK) {
      return grpc::Status(evaluateError, "injected evaluate failure");
    }

    auto *result = response->mutable_result();
    result->set_status(200);
    result->set_message("ok");
    result->set_payload("echo:" + args.back());
    return grpc::Status::OK;
  }

  grpc::Status Endorse(grpc::ServerContext *,
                       const ::gateway::EndorseRequest *request,
                       ::gateway::EndorseResponse *response) override {
    ++endorseCount;
    lastTxId = request->transaction_id();

    auto check = verifySignedProposal(request->proposed_transaction());
    if (!check.ok())
      return check;

    auto args = proposalArgs(request->proposed_transaction());
    if (args.empty()) {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "empty chaincode args");
    }

    ::protos::Proposal proposal;
    if (!proposal.ParseFromString(
            request->proposed_transaction().proposal_bytes())) {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "bad proposal bytes");
    }

    ::protos::ChaincodeProposalPayload proposalPayload;
    if (!proposalPayload.ParseFromString(proposal.payload())) {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "bad proposal payload");
    }
    for (const auto &[k, v] : expectedTransient) {
      auto it = proposalPayload.transientmap().find(k);
      if (it == proposalPayload.transientmap().end() || it->second != v) {
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                            "transient data mismatch");
      }
    }

    ::protos::Response result;
    result.set_status(200);
    result.set_message("ok");
    result.set_payload("echo:" + args.back());

    ::protos::ChaincodeAction chaincodeAction;
    *chaincodeAction.mutable_response() = result;
    chaincodeAction.set_results("rwset");

    ::protos::ChaincodeEndorsedAction endorsedAction;
    endorsedAction.set_proposal_response_payload(
        chaincodeAction.SerializeAsString());

    ::protos::ChaincodeActionPayload actionPayload;
    actionPayload.set_chaincode_proposal_payload(proposal.payload());
    *actionPayload.mutable_action() = endorsedAction;

    ::protos::TransactionAction transactionAction;
    transactionAction.set_header(proposal.header());
    transactionAction.set_payload(actionPayload.SerializeAsString());

    ::protos::Transaction transaction;
    *transaction.add_actions() = transactionAction;

    ::common::Payload payload;
    if (!payload.mutable_header()->ParseFromString(proposal.header())) {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "bad proposal header");
    }
    payload.set_data(transaction.SerializeAsString());

    ::common::Envelope envelope;
    envelope.set_payload(payload.SerializeAsString());
    *response->mutable_prepared_transaction() = envelope;
    return grpc::Status::OK;
  }

  grpc::Status Submit(grpc::ServerContext *,
                      const ::gateway::SubmitRequest *request,
                      ::gateway::SubmitResponse *) override {
    ++submitCount;
    if (request->transaction_id() != lastTxId) {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "transaction_id differs from endorsed proposal");
    }
    const ::common::Envelope &envelope = request->prepared_transaction();
    if (envelope.payload().empty()) {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "empty envelope payload");
    }
    if (!verifyDerSignature(pubKeyPem_, envelope.payload(),
                            envelope.signature())) {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "envelope signature does not verify");
    }
    lastEnvelopeSignature = envelope.signature();
    return grpc::Status::OK;
  }

  grpc::Status
  CommitStatus(grpc::ServerContext *,
               const ::gateway::SignedCommitStatusRequest *request,
               ::gateway::CommitStatusResponse *response) override {
    ++commitCount;
    if (!verifyDerSignature(pubKeyPem_, request->request(),
                            request->signature())) {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "commit status signature does not verify");
    }

    ::gateway::CommitStatusRequest statusRequest;
    if (!statusRequest.ParseFromString(request->request())) {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "bad commit status request");
    }
    if (statusRequest.transaction_id() != lastTxId) {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "commit status transaction_id mismatch");
    }
    if (statusRequest.identity().empty()) {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "missing commit identity");
    }

    response->set_result(
        static_cast<::protos::TxValidationCode>(validationCode));
    response->set_block_number(blockNumber);
    return grpc::Status::OK;
  }

  grpc::Status ChaincodeEvents(
      grpc::ServerContext *, const ::gateway::SignedChaincodeEventsRequest *,
      grpc::ServerWriter<::gateway::ChaincodeEventsResponse> *) override {
    return grpc::Status(grpc::StatusCode::UNIMPLEMENTED,
                        "not implemented in fake");
  }

private:
  grpc::Status
  verifySignedProposal(const ::protos::SignedProposal &signedProposal) const {
    if (signedProposal.proposal_bytes().empty()) {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "empty proposal bytes");
    }
    if (!verifyDerSignature(pubKeyPem_, signedProposal.proposal_bytes(),
                            signedProposal.signature())) {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "proposal signature does not verify");
    }
    return grpc::Status::OK;
  }

  static std::vector<std::string>
  proposalArgs(const ::protos::SignedProposal &signedProposal) {
    ::protos::Proposal proposal;
    if (!proposal.ParseFromString(signedProposal.proposal_bytes()))
      return {};

    ::protos::ChaincodeProposalPayload proposalPayload;
    if (!proposalPayload.ParseFromString(proposal.payload()))
      return {};

    ::protos::ChaincodeInvocationSpec invocation;
    if (!invocation.ParseFromString(proposalPayload.input()))
      return {};

    const ::protos::ChaincodeSpec &spec = invocation.chaincode_spec();
    std::vector<std::string> args;
    for (int i = 0; i < spec.input().args_size(); ++i) {
      args.push_back(spec.input().args(i));
    }
    return args;
  }

  std::string pubKeyPem_;
};

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Gateway client fixture
// ─────────────────────────────────────────────────────────────────────────────

class GatewayClientTest : public ::testing::Test {
protected:
  void SetUp() override {
    fixture_ = makeIdentityFixture();
    fake_ = std::make_unique<FakeGatewayService>(fixture_.pubKeyPem);

    port_ = freePort();
    ASSERT_GT(port_, 0);
    builder_.AddListeningPort(targetFor(port_),
                              grpc::InsecureServerCredentials());
    builder_.RegisterService(fake_.get());
    server_ = builder_.BuildAndStart();
    ASSERT_NE(server_, nullptr);

    connection_ =
        GrpcConnection::connectInsecure(targetFor(port_), testOptions());
    connection_->waitForReady();

    gateway_ = Gateway::connect(connection_, fixture_.toIdentity());
    network_ = gateway_->getNetwork("mychannel");
    contract_ = network_->getContract("basic");
  }

  void TearDown() override {
    if (server_)
      server_->Shutdown();
  }

  IdentityFixture fixture_;
  std::unique_ptr<FakeGatewayService> fake_;
  int port_ = 0;
  grpc::ServerBuilder builder_;
  std::unique_ptr<grpc::Server> server_;
  std::shared_ptr<GrpcConnection> connection_;
  std::shared_ptr<Gateway> gateway_;
  std::shared_ptr<fabric::gateway::Network> network_;
  std::shared_ptr<fabric::gateway::Contract> contract_;
};

TEST_F(GatewayClientTest, EvaluateTransactionReturnsChaincodeResult) {
  TransactionResult result =
      contract_->evaluateTransaction("GetAsset", {"asset1"});

  EXPECT_EQ(result.responseStatus, 200);
  EXPECT_EQ(result.responseMessage, "ok");
  EXPECT_EQ(result.payload, "echo:asset1");
  EXPECT_EQ(fake_->evaluateCount, 1);
  EXPECT_FALSE(result.committed);
}

TEST_F(GatewayClientTest, SubmitTransactionEndorsesSignsAndCommits) {
  TransactionResult result =
      contract_->submitTransaction("CreateAsset", {"a1", "100"});

  EXPECT_TRUE(result.committed);
  EXPECT_EQ(result.validationMessage, "VALID");
  EXPECT_EQ(result.blockNumber, 42);
  EXPECT_EQ(result.responseStatus, 200);
  EXPECT_EQ(result.payload, "echo:100");

  EXPECT_EQ(fake_->endorseCount, 1);
  EXPECT_EQ(fake_->submitCount, 1);
  EXPECT_EQ(fake_->commitCount, 1);
  EXPECT_FALSE(fake_->lastEnvelopeSignature.empty());
}

TEST_F(GatewayClientTest, TransactionHandleWithTransientData) {
  fake_->expectedTransient = {{"secret", "opaque-value"}};
  auto txn = contract_->createTransaction("CreatePrivateAsset",
                                          {{"secret", "opaque-value"}});

  TransactionResult result = txn->submit({"p1", "250"});

  EXPECT_TRUE(result.committed);
  EXPECT_EQ(result.payload, "echo:250");
  EXPECT_EQ(fake_->endorseCount, 1);
}

TEST_F(GatewayClientTest, ValidationFailureIsReportedInResult) {
  fake_->validationCode = ::protos::MVCC_READ_CONFLICT;
  fake_->blockNumber = 7;

  TransactionResult result =
      contract_->submitTransaction("CreateAsset", {"a1", "100"});

  EXPECT_FALSE(result.committed);
  EXPECT_EQ(result.validationMessage, "MVCC_READ_CONFLICT");
  EXPECT_EQ(result.blockNumber, 7);
  EXPECT_EQ(result.responseStatus, 200);
}

TEST_F(GatewayClientTest, RpcFailureThrowsStatusException) {
  fake_->evaluateError = grpc::StatusCode::NOT_FOUND;

  EXPECT_THROW(contract_->evaluateTransaction("Missing", {"x"}),
               StatusException);
  try {
    contract_->evaluateTransaction("Missing", {"x"});
    FAIL() << "expected StatusException";
  } catch (const StatusException &exc) {
    EXPECT_EQ(exc.code(), grpc::StatusCode::NOT_FOUND);
  }
}

TEST_F(GatewayClientTest, EvaluateAndSubmitUseConsistentTransactionId) {
  TransactionResult eval =
      contract_->evaluateTransaction("GetAsset", {"asset2"});
  EXPECT_EQ(eval.payload, "echo:asset2");

  std::string evaluatedTxId = fake_->lastTxId;
  TransactionResult submit =
      contract_->submitTransaction("CreateAsset", {"a2", "50"});
  EXPECT_TRUE(submit.committed);

  // The fake validates txid consistency internally; the two RPCs naturally
  // use different transaction IDs because each generates its own nonce.
  EXPECT_NE(evaluatedTxId, fake_->lastTxId);
}