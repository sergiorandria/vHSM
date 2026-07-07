#ifndef VHSM_LEDGER_LEDGER_CLIENT_H
#define VHSM_LEDGER_LEDGER_CLIENT_H

#include <string>
#include <optional>
#include <memory>
#include "../core/types.h"
#include "ledger_entry.h"

// Forward declare Fabric Gateway types if needed.
// We'll include the actual SDK headers in the .cpp file.
namespace fabric {
    class Gateway;
    class Network;
    class Contract;
} // namespace fabric

namespace vhsm::ledger {

class LedgerClient {
public:
    explicit LedgerClient(const std::string& gateway_endpoint);
    ~LedgerClient();

    // Submits RecordSignature; blocks until endorsed + committed, or times out.
    std::optional<LedgerEntry> submit_record(const SignatureRecord& record);

    // Queries GetRecord by record_id for verification.
    std::optional<LedgerEntry> get_record(const std::string& record_id);

private:
    std::unique_ptr<fabric::Gateway> gateway_;
    std::unique_ptr<fabric::Network> network_;
    std::unique_ptr<fabric::Contract> contract_;
};

}  // namespace vhsm::ledger

#endif // VHSM_LEDGER_LEDGER_CLIENT_H