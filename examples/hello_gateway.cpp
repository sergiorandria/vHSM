#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "util.h"
#include "fabric/grpc/grpc_connection.h"
#include "fabric/identity/identity.h"
#include "fabric/gateway/gateway.h"
#include "fabric/gateway/network.h"
#include "fabric/gateway/contract.h"
#include "fabric/gateway/transaction.h"

namespace {

std::string toHex(const std::string &s) {
  static const char *h = "0123456789abcdef";
  std::string out;
  out.reserve(s.size() * 2);
  for (unsigned char c : s) {
    out.push_back(h[c >> 4]);
    out.push_back(h[c & 0xf]);
  }
  return out;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc < 9) {
    std::cerr << "usage: " << argv[0]
              << " <target> <tlsCa> <cert> <key> <mspId> <channel> "
                 "<chaincode> <function> [submit|evaluate] [args...]\n";
    return 2;
  }

  const std::string target = argv[1];
  const std::string tlsCa = examples::readFile(argv[2]);
  const std::string cert = examples::readFile(argv[3]);
  examples::expectPem(cert, "certificate");
  examples::SecureString key = examples::readSecureFile(argv[4]);
  examples::expectPem(std::string(key.data(), key.size()), "private key");
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
    fabric::grpc::TlsCredentials tls;
    tls.rootCert = tlsCa;

    auto conn = fabric::grpc::GrpcConnection::connect(target, tls);
    if (!conn->isReady()) {
      conn->waitForReady();
    }

    fabric::identity::Identity id(mspId, cert, std::string(key.data(), key.size()));
    key.wipe();  // the example no longer needs its copy; Identity holds its own
    auto gw = fabric::gateway::Gateway::connect(conn, id);
    auto net = gw->getNetwork(channel);
    auto contract = net->getContract(chaincode);

    std::cout << "Connected to " << target << " as " << mspId << "\n";
    std::cout << (mode == "submit" ? "submit " : "evaluate ") << chaincode
              << "." << function;
    for (const auto &a : args) {
      std::cout << " " << a;
    }
    std::cout << "\n";

    fabric::gateway::TransactionResult result =
        (mode == "submit") ? contract->submitTransaction(function, args)
                           : contract->evaluateTransaction(function, args);

    std::cout << "responseStatus  = " << result.responseStatus << "\n";
    std::cout << "responseMessage = " << result.responseMessage << "\n";
    std::cout << "committed       = " << (result.committed ? "true" : "false")
              << "\n";
    std::cout << "txId            = " << result.txId << "\n";
    std::cout << "payload (hex)   = " << toHex(result.payload) << "\n";
    std::cout << "payload (text)  = "
              << (result.payload.size() <= 200 ? result.payload : "(too long)")
              << "\n";

    return result.responseStatus == 200 ? 0 : 1;
  } catch (const std::exception &e) {
    std::cerr << "ERROR: " << e.what() << "\n";
    return 1;
  }
}
