#include "ledger_client.h"
#include "../core/types.h"
#include "ledger_entry.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "fabric/gateway/contract.h"
#include "fabric/gateway/gateway.h"
#include "fabric/gateway/network.h"
#include "fabric/gateway/transaction.h"
#include "fabric/grpc/grpc_connection.h"
#include "fabric/grpc/grpc_status.h"
#include "fabric/crypto/secure_string.h"
#include "fabric/identity/identity.h"
#include "fabric/protoutil/proposal_builder.h"

using json = nlohmann::json;

namespace vhsm::ledger {

namespace {

fabric::grpc::ChannelOptions defaultChannelOptions() {
  fabric::grpc::ChannelOptions options;
  options.keepAliveTime = std::chrono::seconds(5);
  options.keepAliveTimeout = std::chrono::seconds(3);
  options.waitForReadyTimeout = std::chrono::seconds(10);
  return options;
}

} // namespace

LedgerClient::LedgerClient(const std::string &gateway_endpoint,
                           const std::string &cert_path,
                           const std::string &key_path,
                           const std::string &ca_path,
                           const std::string &server_name_override,
                           const std::string &msp_id)
    : msp_id_(msp_id) {
  // Fail-closed: TLS credentials are mandatory. We never construct an
  // insecure channel, so a configuration mistake rejects rather than
  // silently downgrading transport security.
  if (cert_path.empty() || key_path.empty()) {
    throw std::runtime_error("cert_path and key_path are required for mTLS + "
                             "Fabric identity signing");
  }

  fabric::grpc::TlsCredentials tls;
  tls.rootCert = loadFile(ca_path);
  tls.clientCert = fabric::crypto::SecureString(loadFile(cert_path));
  tls.clientKey = fabric::crypto::SecureString(loadFile(key_path));
  tls.serverNameOverride = server_name_override;
  std::shared_ptr<fabric::grpc::GrpcConnection> connection =
      fabric::grpc::GrpcConnection::connect(gateway_endpoint, tls,
                                            defaultChannelOptions());
  if (!connection) {
    throw std::runtime_error("Failed to create gRPC connection to " +
                             gateway_endpoint);
  }
  connection_ = connection;
  connection->waitForReady();

  const std::string certPem = loadFile(cert_path);
  // The private key is moved straight into a self-wiping buffer; we avoid
  // keeping a named plaintext std::string copy of it in this scope.
  fabric::identity::Identity identity(
      msp_id_, certPem, fabric::crypto::SecureString(loadFile(key_path)));
  if (!identity.isValid()) {
    throw std::runtime_error(
        "Invalid Fabric identity: certificate or key is empty");
  }

  gateway_ = fabric::gateway::Gateway::connect(connection, identity);
  if (!gateway_) {
    throw std::runtime_error("Failed to connect to Fabric Gateway");
  }
  network_ = gateway_->getNetwork("signaturechannel");
  if (!network_) {
    throw std::runtime_error("Failed to get network: signaturechannel");
  }
  contract_ = network_->getContract("signature_ledger");
  if (!contract_) {
    throw std::runtime_error("Failed to get contract: signature_ledger");
  }
}

LedgerClient::~LedgerClient() = default;

std::string LedgerClient::loadFile(const std::string &path) const {
  if (path.empty()) {
    return "";
  }
  std::ifstream file(path, std::ios::binary);
  if (!file.is_open()) {
    throw std::runtime_error("Cannot open file: " + path);
  }
  return std::string(std::istreambuf_iterator<char>(file),
                     std::istreambuf_iterator<char>());
}

std::optional<LedgerEntry>
LedgerClient::submit_record(const SignatureRecord &record) {
  std::vector<std::string> args = {
      record.record_id,
      record.key_fingerprint,
      record.payload_digest,
      record.signature_b64,
      std::to_string(record.created_at),
  };

  fabric::gateway::TransactionResult result;
  try {
    result = contract_->submitTransaction("RecordSignature", args);
  } catch (const fabric::grpc::StatusException &e) {
    std::cerr << "Submit failed: " << e.what() << " ("
              << fabric::grpc::statusCodeName(e.code()) << ")" << std::endl;
    return std::nullopt;
  } catch (const std::exception &e) {
    std::cerr << "Failed to submit transaction: " << e.what() << std::endl;
    return std::nullopt;
  }

  if (!result.committed || result.responseStatus != 200) {
    std::cerr << "Transaction not committed: " << result.validationMessage
              << " (status " << result.responseStatus << ")" << std::endl;
    return std::nullopt;
  }

  LedgerEntry entry;
  entry.record_id = record.record_id;
  entry.key_fingerprint = record.key_fingerprint;
  entry.payload_digest = record.payload_digest;
  entry.signature_b64 = record.signature_b64;
  entry.created_at = record.created_at;
  entry.tx_id = result.txId;
  entry.block_number = static_cast<int64_t>(result.blockNumber);
  return entry;
}

std::optional<LedgerEntry>
LedgerClient::get_record(const std::string &record_id) {
  std::vector<std::string> args = {record_id};

  fabric::gateway::TransactionResult result;
  try {
    result = contract_->evaluateTransaction("GetRecord", args);
  } catch (const fabric::grpc::StatusException &e) {
    std::cerr << "Evaluate failed: " << e.what() << " ("
              << fabric::grpc::statusCodeName(e.code()) << ")" << std::endl;
    return std::nullopt;
  } catch (const std::exception &e) {
    std::cerr << "Failed to evaluate transaction: " << e.what() << std::endl;
    return std::nullopt;
  }

  if (result.responseStatus != 200) {
    std::cerr << "Chaincode returned status " << result.responseStatus << ": "
              << result.responseMessage << std::endl;
    return std::nullopt;
  }

  json json_result;
  try {
    json_result = json::parse(result.payload);
  } catch (const std::exception &e) {
    std::cerr << "Failed to parse chaincode response: " << e.what()
              << std::endl;
    return std::nullopt;
  }

  LedgerEntry entry;
  entry.record_id = json_result["record_id"].get<std::string>();
  entry.key_fingerprint = json_result["key_fingerprint"].get<std::string>();
  entry.payload_digest = json_result["payload_digest"].get<std::string>();
  entry.signature_b64 = json_result["signature_b64"].get<std::string>();
  entry.created_at = json_result["created_at"].get<int64_t>();
  entry.tx_id = json_result["tx_id"].get<std::string>();
  entry.block_number = json_result["block_number"].get<int64_t>();
  return entry;
}

} // namespace vhsm::ledger