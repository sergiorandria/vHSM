#ifndef FABRIC_GATEWAY_NETWORK_H
#define FABRIC_GATEWAY_NETWORK_H

#include "contract.h"
#include "gateway.h"
#include <cstdint>
#include <memory>
#include <string>

#if defined(__NETWORK_PEER_ENDPOINT_IMPL) &&                                   \
    (__NETWORK_PEER_ENDPOINT_IMPL_VERSION >= 2)

#define __NETWORK_USE_TLS
#endif // __NETWORK_PEER_ENDPOINT_IMPL

namespace fabric {
class Gateway;

template <class Endpoint, std::size_t PeersSize> class Network {
public:
  explicit Network(Gateway *gateway, const std::string &channelName);
  ~Network();
  class Contract *GetContract(const std::string &chaincodeName);

private:
  Gateway *gateway_;
  std::string channelName_;

  std::array<Endpoint, PeersSize> endpoint_peers;
};
} // namespace fabric

#endif // FABRIC_GATEWAY_NETWORK_H
