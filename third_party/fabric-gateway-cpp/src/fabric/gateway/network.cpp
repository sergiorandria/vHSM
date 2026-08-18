#include "fabric/gateway/network.h"

#include <utility>

#include "fabric/gateway/contract.h"
#include "fabric/gateway/gateway.h"

namespace fabric {
namespace gateway {

Network::Network(std::shared_ptr<Gateway> gateway, std::string channelId)
    : gateway_(std::move(gateway)), channelId_(std::move(channelId)) {}

std::shared_ptr<Contract> Network::getContract(const std::string& chaincodeName) {
    return std::shared_ptr<Contract>(new Contract(shared_from_this(), chaincodeName));
}

std::shared_ptr<Gateway> Network::gateway() {
    return gateway_;
}

} // namespace gateway
} // namespace fabric