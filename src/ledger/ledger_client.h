#ifndef VHSM_LEDGER_LEDGER_CLIENT_H
#define VHSM_LEDGER_LEDGER_CLIENT_H

#include <memory>
#include <optional>
#include <string>

#include "../domain/core/kernel_types.h"
#include "../domain/crypto/crypto_types.h"
#include "../domain/signing/signature_record.h"
#include "ledger_entry.h"

namespace fabric {
namespace grpc {
class ChannelOptions;
class GrpcConnection;
struct TlsCredentials;
} // namespace grpc
namespace identity {
class Identity;
} // namespace identity
namespace gateway {
class Gateway;
class Network;
class Contract;
} // namespace gateway
} // namespace fabric

namespace vhsm::ledger {

/**
 * Client wrapper around the Hyperledger Fabric Gateway SDK
 * (third_party/fabric-gateway-cpp).  Submits signature records and reads
 * them back.  Connection security is selected via CredentialMode.
 */
class LedgerClient {
public:
  /** Credential and transport security mode. TLS/mTLS is mandatory; plaintext
   *  gRPC is intentionally not offered so the client can never fail open. */
  enum class CredentialMode {
    TLS_FROM_FILES, // mTLS from PEM files
#ifdef DEBUG
    TLS_NONE, // Will be used in development environment
#endif        // DEBUG
  };

  /**
   * Build a gateway client.
   * @param gateway_endpoint        gRPC target of the Fabric gateway peer
   * @param cert_path               Client identity + TLS cert PEM (signing +
   * mTLS)
   * @param key_path                Client private key PEM
   * @param ca_path                 PEM of the TLS root of trust (empty = system
   * roots)
   * @param server_name_override    Optional gRPC TLS server-name override
   * @param msp_id                  MSP ID of the signing identity
   */
  LedgerClient(const std::string &gateway_endpoint,
               const std::string &cert_path, const std::string &key_path,
               const std::string &ca_path = "",
               const std::string &server_name_override = "",
               const std::string &msp_id = "vHSMMSP");

  ~LedgerClient();

  // Non-copyable: owns gRPC channel + gateway session.
  LedgerClient(const LedgerClient &) = delete;
  LedgerClient &operator=(const LedgerClient &) = delete;

  /**
   * Submit a signature record to the Fabric ledger via the RecordSignature
   * transaction and block until it is committed.  Returns the resulting
   * ledger entry, or nullopt on any failure.
   */
  virtual std::optional<LedgerEntry>
  submit_record(const SignatureRecord &record);

  /**
   * Query a signature record by record_id via the GetRecord transaction.
   */
  virtual std::optional<LedgerEntry> get_record(const std::string &record_id);

protected:
  // Allows test doubles to construct a LedgerClient without gRPC material.
  LedgerClient() = default;

private:
  std::string loadFile(const std::string &path) const;

  std::shared_ptr<fabric::grpc::GrpcConnection> connection_;
  std::shared_ptr<fabric::gateway::Gateway> gateway_;
  std::shared_ptr<fabric::gateway::Network> network_;
  std::shared_ptr<fabric::gateway::Contract> contract_;
  std::string msp_id_;
};

} // namespace vhsm::ledger

#endif // VHSM_LEDGER_LEDGER_CLIENT_H