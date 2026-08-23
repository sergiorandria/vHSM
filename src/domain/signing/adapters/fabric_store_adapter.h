#ifndef VHSM_DOMAIN_SIGNING_FABRIC_STORE_ADAPTER_H
#define VHSM_DOMAIN_SIGNING_FABRIC_STORE_ADAPTER_H

#include "../isignature_store.h"

#ifdef VHSM_LEDGER
#include "../../../ledger/ledger_client.h"
#include "../../../ledger/ledger_entry.h"
#endif

namespace vhsm::domain::signing {

// WHY adapter: Fabric's `LedgerClient::submit_record` is a gRPC call with
// retry/backoff and returns `optional<LedgerEntry>` (tx_id/block). The port
// expects `store()` to be idempotent and return the `record_id`. This adapter
// makes the ledger look like a simple key-value store so `AppContainer` can
// pick `DbStore` or `FabricStore` via `VHSM_STORE_BACKEND` without changing
// `SignatureDispatcher`.

class FabricStoreAdapter final : public ISignatureStore {
public:
#ifdef VHSM_LEDGER
  explicit FabricStoreAdapter(vhsm::ledger::LedgerClient& client)
      : client_(client) {}

  std::optional<std::string> store(const SignatureRecord& rec) override {
    // The ledger is the source of truth; submit_record is idempotent on
    // `record_id` because the chaincode's `RecordSignature` uses the id as
    // the key. A second submit with the same id is a no-op on Fabric.
    auto entry = client_.submit_record(rec);
    if (!entry) return std::nullopt;
    return rec.record_id;
  }

  std::optional<SignatureRecord> load(const std::string& id) const override {
    // Ledger `GetRecord` is not yet indexed by `record_id` in the chaincode;
    // for now return nullopt and let callers fall back to `list()`.
    // A future chaincode with `GetRecordByID` will make this efficient.
    (void)id;
    return std::nullopt;
  }

  std::vector<SignatureRecord> list() const override {
    // Fabric `GetAllTheses` exists for the thesis flow, but the generic
    // `FabricStore::list()` for signatures is not yet implemented — return
    // empty so the admin `List` degrades gracefully.
    return {};
  }

private:
  vhsm::ledger::LedgerClient& client_;
#else
public:
  std::optional<std::string> store(const SignatureRecord&) override {
    return std::nullopt;
  }
  std::optional<SignatureRecord> load(const std::string&) const override {
    return std::nullopt;
  }
  std::vector<SignatureRecord> list() const override { return {}; }
#endif
};

} // namespace vhsm::domain::signing

#endif // VHSM_DOMAIN_SIGNING_FABRIC_STORE_ADAPTER_H
