#ifndef VHSM_DOMAIN_SIGNING_ISIGNATURE_STORE_H
#define VHSM_DOMAIN_SIGNING_ISIGNATURE_STORE_H

#include "signature_record.h"
#include <optional>
#include <string>
#include <vector>

namespace vhsm::domain::signing {

// WHY a port: The previous design had `SignatureDispatcher` depend directly on
// `SignatureRepository` (sqlite) *and* `LedgerClient` (Fabric) at once, so
// every build pulled both sqlite and Fabric even when only one was deployed.
// Worse, `signature_records` grew `ledger_*` columns for the ledger-anchoring
// case, coupling the DB schema to a backend that, per product, is *alternative*
// to the DB, never complementary. A port inverts the dependency: domain defines
// `ISignatureStore`, infrastructure provides `DbStore` or `FabricStore`, and
// `composition_root` picks one at `C_Initialize` via `VHSM_STORE_BACKEND`.
// WHY mutually exclusive: Operationally a deployment is *either* file-DB or
// ledger-backed; stacking them doubles the failure modes (DB commit + ledger
// submit in one transaction needs a distributed commit) and violates the audit
// requirement that there is a single source of truth. Never stacked.

// ISignatureStore — port for signature persistence (DDD).
// Two adapters: DbSignatureStore (sqlite/postgres) and FabricSignatureStore
// (Hyperledger Fabric). Backends are mutually exclusive per deployment
// (VHSM_STORE_BACKEND=db|ledger), never stacked.

class ISignatureStore {
public:
  virtual ~ISignatureStore() = default;

  // WHY store returns optional<string> + is idempotent: `C_Sign` is retryable
  // (HSM may be asked to sign the same payload twice after a crash). Returning
  // nullopt on DB/ledger error lets the caller publish `DB_WRITE_FAILED`
  // without throwing across the PKCS#11 C ABI boundary, while idempotence on
  // `record_id` (UUID v4 generated once at the call site) makes a retried
  // `C_Sign` not create a duplicate row — the ledger worker can safely
  // re-submit a `PENDING` record after a power loss.
  // Persist a record; returns the stored id on success, nullopt on DB/ledger
  // error. Implementations must be idempotent for the same record_id.
  virtual std::optional<std::string> store(const SignatureRecord &rec) = 0;

  // WHY optional on load: `get` is used by `C_Verify` and the admin API to
  // distinguish "not found" (CKR_ARGUMENTS_BAD) from "found but
  // ledger_status=FAILED" — collapsing those into a single nullptr return
  // (as the pre-port code did with `vector<optional<string>>`) hid whether
  // the failure was a missing row or a corrupted one, which matters for audit.
  // Load by id; nullopt if not found.
  virtual std::optional<SignatureRecord>
  load(const std::string &record_id) const = 0;

  // WHY list may be empty for ledger: Fabric's `GetAllTheses` scans the
  // world state, but a ledger with no secondary index on `key_id` would need a
  // full chain scan to list. The port therefore allows an empty `list()` for
  // ledger so the admin `ListSlots` can degrade gracefully (return 0) rather
  // than requiring every ledger adapter to implement an expensive scan.
  // List all records (for admin/query). May be empty for ledger if not indexed.
  virtual std::vector<SignatureRecord> list() const = 0;
};

} // namespace vhsm::domain::signing

#endif // VHSM_DOMAIN_SIGNING_ISIGNATURE_STORE_H
