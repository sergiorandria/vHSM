#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "fabric/gateway/contract.h"
#include "fabric/gateway/gateway.h"
#include "fabric/gateway/network.h"
#include "fabric/gateway/transaction.h"
#include "fabric/grpc/grpc_connection.h"
#include "fabric/identity/identity.h"
#include "fabric/identity/wallet.h"
#include "util.h"

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
} // namespace

// Connect to a Fabric gateway using an identity loaded from the hardened
// wallet (no raw key material is handled by the application at runtime).
//
// usage: wallet_gateway <target> <tlsCa> <walletDir> <masterKeyFile> <label>
//        <channel> <chaincode> <function> [submit|evaluate] [args...]
int main(int argc, char **argv) {
  if (argc < 9) {
    std::cerr
        << "usage: " << argv[0]
        << " <target> <tlsCa> <walletDir> <masterKeyFile> <label>"
           " <channel> <chaincode> <function> [submit|evaluate] [args...]\n"
        << "  masterKeyFile must contain 64 hex chars (32 bytes)\n";
    return 2;
  }
  const std::string target = argv[1];
  const std::string tlsCaFile = argv[2];
  const std::string walletDir = argv[3];
  const std::string masterKeyFile = argv[4];
  const std::string label = argv[5];
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
    // Validate the wrapping key up front; the SecureString scrubs its copy when
    // it leaves scope. It is then exposed to the process environment via
    // setenv() (the wallet reads it from there) — an unavoidable leak surface
    // of the current wallet API, called out so it isn't mistaken for safe.
    examples::SecureString masterKey = examples::readSecureFile(masterKeyFile);
    examples::expectMasterKeyHex(
        std::string(masterKey.data(), masterKey.size()));
    setenv("FABRIC_WALLET_MASTER_KEY", masterKey.data(), 1);

    auto wres = fabric::identity::CustomHardenedWallet::create(walletDir);
    if (!wres.has_value()) {
      std::cerr << "wallet open failed: " << wres.error().message() << "\n";
      return 1;
    }
    auto idres = wres.value().get(label);
    if (!idres.has_value()) {
      std::cerr << "identity '" << label
                << "' not found: " << idres.error().message() << "\n";
      return 1;
    }
    fabric::identity::Identity id = *idres.value();

    fabric::grpc::TlsCredentials tls;
    tls.rootCert = examples::readFile(tlsCaFile);
    auto conn = fabric::grpc::GrpcConnection::connect(target, tls);
    if (!conn->isReady()) {
      conn->waitForReady();
    }

    auto gw = fabric::gateway::Gateway::connect(conn, id);
    auto net = gw->getNetwork(channel);
    auto cc = net->getContract(chaincode);

    std::cout << "Connected as " << id.getMSPID() << " (identity '" << label
              << "')\n";
    fabric::gateway::TransactionResult result =
        (mode == "submit") ? cc->submitTransaction(function, args)
                           : cc->evaluateTransaction(function, args);

    std::cout << "responseStatus = " << result.responseStatus << "\n";
    std::cout << "responseMessage= " << result.responseMessage << "\n";
    std::cout << "committed      = " << (result.committed ? "true" : "false")
              << "\n";
    std::cout << "txId           = " << result.txId << "\n";
    std::cout << "payload (hex)  = " << toHex(result.payload) << "\n";
    std::cout << "payload (text) = "
              << (result.payload.size() <= 200 ? result.payload : "(too long)")
              << "\n";
    return result.responseStatus == 200 ? 0 : 1;
  } catch (const std::exception &e) {
    std::cerr << "ERROR: " << e.what() << "\n";
    return 1;
  }
}
