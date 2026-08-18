#include "fabric/gateway/contract.h"

#include <utility>

#include "fabric/gateway/gateway.h"
#include "fabric/gateway/network.h"

namespace fabric {
namespace gateway {

Contract::Contract(std::shared_ptr<Network> network, std::string chaincodeName)
    : network_(std::move(network)), chaincodeName_(std::move(chaincodeName)) {}

std::string Contract::channelId() const {
    return network_->channelId();
}

std::shared_ptr<Network> Contract::network() {
    return network_;
}

std::shared_ptr<Gateway> Contract::gateway() {
    return network_->gateway();
}

TransactionResult Contract::evaluateTransaction(const std::string& name,
                                                const std::vector<std::string>& args) {
    return createTransaction(name)->evaluate(args);
}

TransactionResult Contract::submitTransaction(const std::string& name,
                                              const std::vector<std::string>& args) {
    return createTransaction(name)->submit(args);
}

std::shared_ptr<Transaction> Contract::createTransaction(const std::string& name) {
    return std::shared_ptr<Transaction>(new Transaction(shared_from_this(), name, {}));
}

std::shared_ptr<Transaction> Contract::createTransaction(
    const std::string& name,
    const std::map<std::string, std::string>& transient) {
    return std::shared_ptr<Transaction>(new Transaction(shared_from_this(), name, transient));
}

} // namespace gateway
} // namespace fabric