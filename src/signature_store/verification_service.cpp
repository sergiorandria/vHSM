#include "verification_service.h"

namespace vhsm::signature_store {
namespace db {

VerificationService::VerificationService(
    IDbConnection &conn, vhsm::ledger::LedgerClient &ledger_client,
    SignatureRepository &signature_repository)
    : v_core_(conn, ledger_client, signature_repository) {}

VerificationService::VerificationResult
VerificationService::verify_signature(const std::string &signature_id,
                                      bool check_ledger) {
  // Public API: reject degenerate input before delegating to the core.
  if (signature_id.empty()) {
    VerificationResult result;
    result.error_detail = "signature_id must not be empty";
    return result;
  }
  return v_core_.v_verify(signature_id, check_ledger);
}

} // namespace db
} // namespace vhsm::signature_store
