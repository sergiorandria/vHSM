#ifndef VHSM_DOMAIN_SIGNING_ISIGNATURE_STORE_H
#define VHSM_DOMAIN_SIGNING_ISIGNATURE_STORE_H

#include "signature_record.h"
#include <optional>
#include <string>
#include <vector>

namespace vhsm::domain::signing {

// ISignatureStore — port for signature persistence (DDD).
// Two adapters: DbSignatureStore (sqlite/postgres) and FabricSignatureStore
// (Hyperledger Fabric). Backends are mutually exclusive per deployment
// (VHSM_STORE_BACKEND=db|ledger), never stacked.

class ISignatureStore {
public:
  virtual ~ISignatureStore() = default;

  // Persist a record; returns the stored id on success, nullopt on DB/ledger
  // error. Implementations must be idempotent for the same record_id.
  virtual std::optional<std::string> store(const SignatureRecord& rec) = 0;

  // Load by id; nullopt if not found.
  virtual std::optional<SignatureRecord> load(const std::string& record_id) const = 0;

  // List all records (for admin/query). May be empty for ledger if not indexed.
  virtual std::vector<SignatureRecord> list() const = 0;
};

} // namespace vhsm::domain::signing

#endif // VHSM_DOMAIN_SIGNING_ISIGNATURE_STORE_H
