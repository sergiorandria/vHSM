#ifndef VHSM_SIGSTORE_INTERNAL_SIGNATURE_QUERY_CORE_H
#define VHSM_SIGSTORE_INTERNAL_SIGNATURE_QUERY_CORE_H

#include <optional>
#include <string>
#include <vector>

#include "../../core/types.h"
#include "../../keystore/token.h"
#include "../../ledger/ledger_client.h"
#include "../db_connection.h"
#include "../db_result_set.h"
#include "../signature_repository.h"

namespace vhsm::signature_store {
namespace db {
namespace internal {

// Result of a signature query / verification.  Defined here (not in the facade)
// so the core owns its contract and the facade simply aliases it.
struct v_SignatureQueryVerificationResult_M1 {
    bool record_found = false;               // present in the local DB
    bool ledger_cross_check_ok = false;      // ledger entry matches local row
    std::optional<std::string> error_detail;
    std::optional<std::string> ledger_tx_id;
    std::optional<int64_t>     ledger_block_num;
    std::string                ledger_status; // PENDING / COMMITTED / FAILED
    std::optional<std::string> payload_digest;
};

// Core business logic behind SignatureQuery.  The facade validates the
// caller-supplied identifiers / time range and delegates here; this class owns
// all SQL queries and ledger cross-checks.
class v_SignatureQueryCore_M1 {
public:
    v_SignatureQueryCore_M1(IDbConnection& conn, vhsm::keystore::Token& token);

    std::optional<std::vector<std::optional<std::string>>> v_get_signature_by_id(
        const std::string& signature_id) const;

    v_SignatureQueryVerificationResult_M1 v_verify_signature(const std::string& signature_id) const;

    v_SignatureQueryVerificationResult_M1 v_verify_signature(const std::string& signature_id,
                                                             vhsm::ledger::LedgerClient& ledger);

    std::vector<std::string> v_get_signature_ids_by_key_fingerprint(const std::string& key_fingerprint);

    std::vector<std::string> v_get_signature_ids_by_time_range(int64_t start_time, int64_t end_time);

private:
    IDbConnection& v_conn_;
    SignatureRepository v_signature_repository_;
};

}  // namespace internal
}  // namespace db
}  // namespace vhsm::signature_store

#endif // VHSM_SIGSTORE_INTERNAL_SIGNATURE_QUERY_CORE_H
