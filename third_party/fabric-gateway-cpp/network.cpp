#include "network.h"
#include "contract.h"

namespace fabric {

Network::Network(Gateway* gateway, const std::string& channelName)
    : gateway_(gateway), channelName_(channelName) {
}

Network::~Network() {
    // We don't own the gateway, so we don't delete it.
}

class Contract* Network::GetContract(const std::string& chaincodeName) {
    return new Contract(chaincodeName, this);
}

} // namespace fabric