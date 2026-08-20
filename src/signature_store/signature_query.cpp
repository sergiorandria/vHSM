#include "signature_query.h"

namespace vhsm::signature_store {
namespace db {

SignatureQuery::SignatureQuery(IDbConnection &conn, keystore::Token &token)
    : v_core_(conn, token) {}

std::optional<std::vector<std::optional<std::string>>>
SignatureQuery::get_signature_by_id(const std::string &signature_id) const {
  // Public API: reject degenerate input before delegating to the core.
  if (signature_id.empty()) {
    return std::nullopt;
  }
  return v_core_.v_get_signature_by_id(signature_id);
}

SignatureQuery::VerificationResult
SignatureQuery::verify_signature(const std::string &signature_id) const {
  // Public API: reject degenerate input before delegating to the core.
  if (signature_id.empty()) {
    VerificationResult result;
    result.error_detail = "signature_id must not be empty";
    return result;
  }
  return v_core_.v_verify_signature(signature_id);
}

SignatureQuery::VerificationResult
SignatureQuery::verify_signature(const std::string &signature_id,
                                 vhsm::ledger::LedgerClient &ledger) {
  // Public API: reject degenerate input before delegating to the core.
  if (signature_id.empty()) {
    VerificationResult result;
    result.error_detail = "signature_id must not be empty";
    return result;
  }
  return v_core_.v_verify_signature(signature_id, ledger);
}

std::vector<std::string> SignatureQuery::get_signature_ids_by_key_fingerprint(
    const std::string &key_fingerprint) {
  // Public API: reject degenerate input before delegating to the core.
  if (key_fingerprint.empty()) {
    return {};
  }
  return v_core_.v_get_signature_ids_by_key_fingerprint(key_fingerprint);
}

std::vector<std::string>
SignatureQuery::get_signature_ids_by_time_range(int64_t start_time,
                                                int64_t end_time) {
  // Public API: reject an inverted range before delegating to the core.
  if (start_time > end_time) {
    return {};
  }
  return v_core_.v_get_signature_ids_by_time_range(start_time, end_time);
}

} // namespace db
} // namespace vhsm::signature_store
