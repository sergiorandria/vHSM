// live_gateway_client.cpp — vHSM integration test for the C++ Fabric Gateway
// SDK (third_party/fabric-gateway-cpp). Connects to a *real* Fabric peer over
// TLS, authenticates with an enrolled identity, and evaluates a chaincode
// transaction (default: the built-in `qscc` GetChainInfo on a channel).
//
// Usage:
//   live_gateway_client <peerHost:port> <tlsCaPem> <certPem> <keyPem>
//                       <mspId> <channel> <chaincode> <function> [mode] [args...]
//
// Example (against the Conf_with_fabric-CA network):
//   live_gateway_client localhost:7052
//     organizations/peerOrganizations/misa.university.com/peers/peer0.misa.university.com/tls/ca.crt
//     organizations/peerOrganizations/misa.university.com/users/User1@misa.university.com/msp/signcerts/cert.pem
//     organizations/peerOrganizations/misa.university.com/users/User1@misa.university.com/msp/keystore/<key>_sk
//     misaMSP canaltest qscc GetChainInfo canaltest

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "fabric/grpc/grpc_connection.h"
#include "fabric/identity/identity.h"
#include "fabric/gateway/gateway.h"
#include "fabric/gateway/network.h"
#include "fabric/gateway/contract.h"

using fabric::grpc::GrpcConnection;
using fabric::grpc::TlsCredentials;
using fabric::identity::Identity;

static std::string readFile(const std::string &path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) {
    throw std::runtime_error("cannot open file: " + path);
  }
  std::stringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

static std::string toHex(const std::string &in) {
  static const char *hex = "0123456789abcdef";
  std::string out;
  out.reserve(in.size() * 2);
  for (unsigned char c : in) {
    out.push_back(hex[c >> 4]);
    out.push_back(hex[c & 0xf]);
  }
  return out;
}

int main(int argc, char **argv) {
  if (argc < 9) {
    std::cerr << "usage: " << (argc > 0 ? argv[0] : "live_gateway_client")
              << " <peerHost:port> <tlsCaPem> <certPem> <keyPem> "
                 "<mspId> <channel> <chaincode> <function> [args...]\n";
    return 2;
  }

  const std::string target = argv[1];
  const std::string tlsCa = readFile(argv[2]);
  const std::string cert = readFile(argv[3]);
  const std::string key = readFile(argv[4]);
  const std::string mspId = argv[5];
  const std::string channel = argv[6];
  const std::string chaincode = argv[7];
  const std::string function = argv[8];

  std::string mode = "evaluate";
  std::vector<std::string> args;
  int argStart = 9;
  if (argc > 9) {
    std::string maybe = argv[9];
    if (maybe == "submit" || maybe == "evaluate") {
      mode = maybe;
      argStart = 10;
    }
  }
  for (int i = argStart; i < argc; ++i) {
    args.emplace_back(argv[i]);
  }

  try {
    TlsCredentials tls;
    tls.rootCert = tlsCa; // SAN of peer cert includes "localhost"

    auto conn = GrpcConnection::connect(target, tls);
    if (!conn->isReady()) {
      conn->waitForReady();
    }

    Identity id(mspId, cert, key);
    auto gw = fabric::gateway::Gateway::connect(conn, id);
    auto net = gw->getNetwork(channel);
    auto contract = net->getContract(chaincode);

    std::cout << "Connected to " << target << " as " << mspId << "\n";
    std::cout << (mode == "submit" ? "Submitting " : "Evaluating ") << chaincode
              << "." << function;
    for (const auto &a : args) {
      std::cout << " " << a;
    }
    std::cout << "\n";

    fabric::gateway::TransactionResult result =
        (mode == "submit") ? contract->submitTransaction(function, args)
                           : contract->evaluateTransaction(function, args);

    std::cout << "responseStatus   = " << result.responseStatus << "\n";
    std::cout << "responseMessage  = " << result.responseMessage << "\n";
    std::cout << "txId             = " << result.txId << "\n";
    std::cout << "payload bytes    = " << result.payload.size() << "\n";
    std::cout << "payload (hex)    = " << toHex(result.payload) << "\n";

    return result.responseStatus == 200 ? 0 : 1;
  } catch (const std::exception &e) {
    std::cerr << "ERROR: " << e.what() << "\n";
    return 1;
  }
}
