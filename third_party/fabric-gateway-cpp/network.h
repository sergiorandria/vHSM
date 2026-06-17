#ifndef FABRIC_GATEWAY_NETWORK_H
#define FABRIC_GATEWAY_NETWORK_H

#include "contract.h"

#include <string>

namespace fabric {

class Network {
public:
    class Contract* GetContract(const std::string& chaincodeName);
};

} // namespace fabric

#endif // FABRIC_GATEWAY_NETWORK_H