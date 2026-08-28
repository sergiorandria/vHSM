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

  // Result of a ledger-side policy/attestation verification.
  struct PolicyVerification {
    bool ok = false;
    std::string reason;
  };

  /**
   * Ask the ledger's PolicyContract whether `actor` may sign key `key_id` with
   * `mechanism` at `now_ms`, taking the on-chain attestation registry and the
   * published policy into account. This is the authoritative quorum check used
   * by the sign path when attestations are required. Returns {ok=false} on any
   * ledger error so callers fail closed.
   */
  virtual PolicyVerification verify_policy(const std::string &key_id,
                                           const std::string &actor,
                                           const std::string &mechanism,
                                           int64_t now_ms);

  /**
   * Anchor the current audit hash-chain tail on the ledger via the
   * RecordAuditTail transaction. Used to make the tamper-evident audit log
   * externally verifiable (a truncated/forged local audit file is detectable
   * because its tail no longer matches the anchored value). Returns false on
   * any ledger error so callers can log but never block the audit path.
   */
  virtual bool publish_audit_tail(const std::string &tail_hash, int64_t seq,
                                 const std::string &timestamp);

  // Returns the most recently anchored audit tail hash from the ledger, or
  // nullopt if none has been anchored yet. Used by the integrity verifier to
  // confirm the local audit file's tail matches the external anchor.
  virtual std::optional<std::string> get_latest_audit_tail_hash();

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