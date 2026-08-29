#ifndef VHSM_SIGSTORE_INTERNAL_VERIFICATION_SERVICE_CORE_H
#define VHSM_SIGSTORE_INTERNAL_VERIFICATION_SERVICE_CORE_H

#include <optional>
#include <string>

#include "../../ledger/ledger_client.h"
#include "../db_connection.h"
#include "../signature_repository.h"

namespace vhsm::signature_store {
namespace db {
namespace internal {

// Result of a verification operation.  Defined here (not in the facade) so the
// core owns its contract and the facade simply aliases it.
struct v_VerificationResult_M1 {
  bool local_record_exists = false;  // Record found in local DB
  bool ledger_record_exists = false; // Record found in ledger (if checked)
  bool payload_digest_match =
      false; // Ledger payload digest matches local payload digest
  bool signature_b64_match = false; // Ledger signature matches local signature
  bool key_fingerprint_match =
      false; // Ledger key fingerprint matches local key fingerprint
  bool integrity_hmac_ok = false; // Local row-integrity HMAC verified
  std::optional<std::string> error_detail;
  std::optional<std::string> ledger_tx_id;
  std::optional<int64_t> ledger_block_num;
};

// Core business logic behind VerificationService.  The facade validates the
// caller-supplied signature_id and delegates here; this class owns the
// local-vs-ledger comparison and never validates input itself.
class v_VerificationServiceCore_M1 {
public:
  v_VerificationServiceCore_M1(IDbConnection &conn,
                               vhsm::ledger::LedgerClient &ledger_client,
                               SignatureRepository &signature_repository);

  v_VerificationResult_M1 v_verify(const std::string &signature_id,
                                   bool check_ledger);

private:
  IDbConnection &v_conn_;
  vhsm::ledger::LedgerClient &v_ledger_client_;
  SignatureRepository &v_signature_repository_;
};

} // namespace internal
} // namespace db
} // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_INTERNAL_VERIFICATION_SERVICE_CORE_H
