#ifndef FABRIC_GATEWAY_CONTRACT_H
#define FABRIC_GATEWAY_CONTRACT_H

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "fabric/gateway/transaction.h"

namespace fabric {
namespace gateway {

class Gateway;
class Network;

/**
 * A chaincode contract installed on a network. Provides transaction
 * evaluation and submission plus explicit transaction handles.
 */
class Contract : public std::enable_shared_from_this<Contract> {
public:
    /**
     * Evaluate a transaction (query) and return the chaincode response.
     * @param name Transaction / function name
     * @param args Function arguments (excluding the name)
     * @return Chaincode response
     */
    TransactionResult evaluateTransaction(const std::string& name,
                                          const std::vector<std::string>& args = {});

    /**
     * Submit a transaction and wait for it to be committed.
     * @param name Transaction / function name
     * @param args Function arguments (excluding the name)
     * @return Commit outcome including the chaincode response
     */
    TransactionResult submitTransaction(const std::string& name,
                                        const std::vector<std::string>& args = {});

    /**
     * Create a transaction handle for later evaluation or submission.
     * @param name Transaction / function name
     * @return Transaction handle
     */
    std::shared_ptr<Transaction> createTransaction(const std::string& name);

    /**
     * Create a transaction handle with transient data (never persisted).
     * @param name Transaction / function name
     * @param transient Transient key/value data
     * @return Transaction handle
     */
    std::shared_ptr<Transaction> createTransaction(
        const std::string& name,
        const std::map<std::string, std::string>& transient);

    const std::string& chaincodeName() const { return chaincodeName_; }
    std::string channelId() const;
    std::shared_ptr<Network> network();
    std::shared_ptr<Gateway> gateway();

private:
    friend class Network;
    Contract(std::shared_ptr<Network> network, std::string chaincodeName);

    std::shared_ptr<Network> network_;
    std::string chaincodeName_;
};

} // namespace gateway
} // namespace fabric

#endif // FABRIC_GATEWAY_CONTRACT_H