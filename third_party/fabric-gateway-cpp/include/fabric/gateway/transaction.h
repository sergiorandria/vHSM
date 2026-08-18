#ifndef FABRIC_GATEWAY_TRANSACTION_H
#define FABRIC_GATEWAY_TRANSACTION_H

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace fabric {
namespace gateway {

class Contract;

/**
 * Result of a chaincode evaluation or submission.
 */
struct TransactionResult {
    bool committed = false;                      // true when validation code == VALID
    int32_t validationCode = -1;                 // protos::TxValidationCode on commit
    std::string validationMessage;               // human-readable validation result
    uint64_t blockNumber = 0;                    // block containing the committed tx
    int32_t responseStatus = 0;                  // chaincode response status (200 = success)
    std::string responseMessage;                 // chaincode response message
    std::string payload;                         // chaincode response payload
    std::string txId;                             // transaction ID assigned by the client
};

/**
 * A pending transaction against a chaincode contract. Constructed via
 * Contract::createTransaction and executed with evaluate() or submit().
 */
class Transaction {
public:
    /**
     * Evaluate the transaction (query) without submitting it to the ledger.
     * @param args Chaincode function name followed by arguments
     * @return Chaincode response
     */
    TransactionResult evaluate(const std::vector<std::string>& args);

    /**
     * Endorse, submit and wait for the transaction to commit.
     * @param args Chaincode function name followed by arguments
     * @return Commit outcome including the chaincode response
     */
    TransactionResult submit(const std::vector<std::string>& args);

    TransactionResult submit();

    const std::string& name() const { return name_; }

private:
    friend class Contract;
    Transaction(std::shared_ptr<Contract> contract,
                std::string name,
                std::map<std::string, std::string> transient);

    std::shared_ptr<Contract> contract_;
    std::string name_;
    std::map<std::string, std::string> transient_;
};

} // namespace gateway
} // namespace fabric

#endif // FABRIC_GATEWAY_TRANSACTION_H