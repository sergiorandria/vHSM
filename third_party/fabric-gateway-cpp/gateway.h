#ifndef FABRIC_GATEWAY_GATEWAY_H
#define FABRIC_GATEWAY_GATEWAY_H

#include <string>
#include <memory>
#include <curl/curl.h>

namespace fabric {

class Network;

class Gateway {
public:
    static Gateway* Create(const std::string& endpoint, void* credentials);
    ~Gateway();
    class Network* GetNetwork(const std::string& channelName);
    void Shutdown();

private:
    Gateway(const std::string& endpoint, void* credentials);
    std::string endpoint_;
    void* credentials_;
    // We'll keep a CURL handle for convenience, but we can also create per request.
    CURL* curl_;
    // To avoid copying
    Gateway(const Gateway&) = delete;
    Gateway& operator=(const Gateway&) = delete;
};

} // namespace fabric

#endif // FABRIC_GATEWAY_GATEWAY_H