#ifndef FABRIC_GATEWAY_GATEWAY_H
#define FABRIC_GATEWAY_GATEWAY_H

#include <string>

namespace fabric {

class Gateway {
public:
    static Gateway* Create(const std::string& endpoint, void* credentials);
    ~Gateway();
    class Network* GetNetwork(const std::string& channelName);
    void Shutdown();
};

} // namespace fabric

#endif // FABRIC_GATEWAY_GATEWAY_H