#ifndef FABRIC_GATEWAY_NETWORK_H
#define FABRIC_GATEWAY_NETWORK_H

#include "contract.h"
#include <string>
#include <memory>

namespace fabric {

class Gateway;

class Network {
public:
    explicit Network(Gateway* gateway, const std::string& channelName);
    ~Network();
    class Contract* GetContract(const std::string& chaincodeName);

private:
    Gateway* gateway_;
    std::string channelName_;
    
    // To avoid copying
    //Network(const Network&) = delete;
    //Network& operator=(const Network&) = delete;
};

} // namespace fabric

#endif // FABRIC_GATEWAY_NETWORK_H