#include <cstdlib>
#include <iostream>
#include <string>

#include "util.h"
#include "fabric/identity/identity.h"
#include "fabric/identity/wallet.h"

// Store a PKI identity (cert + key + MSP ID) into a hardened wallet. The wallet
// encrypts the private key at rest with AES-256-GCM; the wrapping key is taken
// from the FABRIC_WALLET_MASTER_KEY environment variable (set below from a
// file, never from a command-line argument — argv is world-readable via
// /proc and `ps`).
//
// usage: wallet_store <walletDir> <label> <certFile> <keyFile> <mspId>
//        <masterKeyFile>
int main(int argc, char **argv) {
  if (argc != 7) {
    std::cerr << "usage: " << argv[0]
              << " <walletDir> <label> <certFile> <keyFile> <mspId>"
                 " <masterKeyFile>\n"
              << "  masterKeyFile must contain 64 hex chars (32 bytes)\n";
    return 2;
  }
  const std::string walletDir = argv[1];
  const std::string label = argv[2];
  const std::string certFile = argv[3];
  const std::string keyFile = argv[4];
  const std::string mspId = argv[5];
  const std::string masterKeyFile = argv[6];

  try {
    // Public cert: validated as PEM, held in a normal string (not secret).
    const std::string cert = examples::readFile(certFile);
    examples::expectPem(cert, "certificate");

    // Private key: read into a SecureString so the example's own copy is wiped
    // on scope exit. The buffer is consumed by setenv() and then destroyed.
    examples::SecureString key = examples::readSecureFile(keyFile);
    examples::expectPem(std::string(key.data(), key.size()), "private key");

    // Wrapping key: from a file, not argv. Validated before use, then the
    // SecureString's destructor scrubs the in-memory copy.
    examples::SecureString masterKey = examples::readSecureFile(masterKeyFile);
    examples::expectMasterKeyHex(std::string(masterKey.data(), masterKey.size()));
    setenv("FABRIC_WALLET_MASTER_KEY", masterKey.data(), 1);

    auto wres = fabric::identity::CustomHardenedWallet::create(walletDir);
    if (!wres.has_value()) {
      std::cerr << "wallet open failed: " << wres.error().message() << "\n";
      return 1;
    }
    fabric::identity::CustomHardenedWallet &wallet = wres.value();
    if (!wallet.hasMasterKey()) {
      std::cerr << "master key unavailable (check FABRIC_WALLET_MASTER_KEY)\n";
      return 1;
    }

    fabric::identity::Identity id(mspId, cert, std::string(key.data(), key.size()));
    auto put = wallet.put(label, id);
    if (!put.has_value()) {
      std::cerr << "put failed: " << put.error().message() << "\n";
      return 1;
    }
    std::cout << "stored identity '" << label << "' (" << mspId << ") in "
              << walletDir << "\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "ERROR: " << e.what() << "\n";
    return 1;
  }
}
