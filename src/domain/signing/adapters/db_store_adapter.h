#ifndef VHSM_DOMAIN_SIGNING_DB_STORE_ADAPTER_H
#define VHSM_DOMAIN_SIGNING_DB_STORE_ADAPTER_H

#include "../../../keystore/token.h"
#include "../../../signature_store/db_connection.h"
#include "../../../signature_store/signature_repository.h"
#include "../isignature_store.h"

namespace vhsm::domain::signing {

// WHY adapter: The old SignatureRepository exposed `insert(created_at, slot_id,
// ...)` with 12 positional args and returned `optional<string>` via raw SQL.
// New domain code should talk to `ISignatureStore::store(SignatureRecord)` with
// a single aggregate, so the DB specifics (column order, `ledger_*` defaults)
// stay hidden. This adapter translates the port call into the existing
// repository without rewriting the repository.

class DbStoreAdapter final : public ISignatureStore {
public:
  DbStoreAdapter(vhsm::signature_store::db::IDbConnection &db,
                 vhsm::keystore::Token &token)
      : repo_(db, token) {}

  std::optional<std::string> store(const SignatureRecord &rec) override {
    return repo_.insert(rec.created_at, rec.slot_id, rec.token_label,
                        rec.key_id, rec.key_fingerprint, rec.mechanism,
                        rec.digest_algorithm, rec.payload_digest,
                        rec.payload_size, rec.signature_b64, rec.session_handle,
                        rec.user_label, rec.app_context);
  }

  std::optional<SignatureRecord> load(const std::string &id) const override {
    auto row = repo_.get_by_id(id);
    if (!row)
      return std::nullopt;
    // Minimal mapping for the port — full field mapping is in the repository;
    // for the adapter we reconstruct the aggregate from the row vector.
    // This keeps the adapter thin; a future slice can move the mapping into
    // the repository itself (returning `optional<SignatureRecord>` directly).
    SignatureRecord rec;
    rec.record_id = id;
    // Only id is guaranteed; other fields are best-effort for the port.
    // Callers that need full fidelity should use the repository directly
    // until the port is fully adopted.
    if (row->size() > 0 && (*row)[0])
      rec.record_id = *(*row)[0];
    return rec;
  }

  std::vector<SignatureRecord> list() const override {
    // For DB, list is via SignatureQuery; for the port we return empty until
    // the query is ported. This keeps the adapter buildable without pulling
    // the query into the domain.
    return {};
  }

private:
  mutable vhsm::signature_store::db::SignatureRepository repo_;
};

} // namespace vhsm::domain::signing

#endif // VHSM_DOMAIN_SIGNING_DB_STORE_ADAPTER_H
