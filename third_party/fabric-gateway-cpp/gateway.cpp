#include "gateway.h"
#include "network.h"
#include <stdexcept>

namespace fabric {

Gateway* Gateway::Create(const std::string& endpoint, void* credentials) {
    // Initialize libcurl if not already done globally? We'll do it per instance for simplicity.
    // In a real application, you should initialize libcurl once.
    // We'll initialize in the constructor and cleanup in destructor.
    return new Gateway(endpoint, credentials);
}

Gateway::Gateway(const std::string& endpoint, void* credentials)
    : endpoint_(endpoint), credentials_(credentials), curl_(nullptr) {
    curl_ = curl_easy_init();
    if (!curl_) {
        throw std::runtime_error("Failed to initialize CURL");
    }
}

Gateway::~Gateway() {
    if (curl_) {
        curl_easy_cleanup(curl_);
    }
}

class Network* Gateway::GetNetwork(const std::string& channelName) {
    return new Network(this, channelName);
}

void Gateway::Shutdown() {
    // In this implementation, we don't have anything to shut down besides the destructor.
    // We could delete the gateway, but that is done by the caller.
    // For now, we do nothing.
}

} // namespace fabric