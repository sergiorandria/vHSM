#ifndef FABRIC_GATEWAY_NETWORK_H
#define FABRIC_GATEWAY_NETWORK_H

#include "contract.h"
#include <cstdint>
#include <memory>
#include <string>
#include <type_traits>

#if defined(__NETWORK_PEER_ENDPOINT_IMPL) &&                                   \
    (__NETWORK_PEER_ENDPOINT_IMPL_VERSION >= 2)

#define __NETWORK_USE_TLS
#endif // __NETWORK_PEER_ENDPOINT_IMPL

namespace fabric {
class Gateway;

template <class Endpoint, std::size_t N> 
class Network {
public:
  explicit Network(Gateway *gateway, const std::string &channelName);
  ~Network();
  
  Contract<N> *GetContract(const std::string &chaincodeName);
  inline Contract<N> *CreateContract(const Contract<N>& other) 
    requires std::is_integral_v<decltype(N)> { 
      contracts_ = other;
  } 

private:
  Gateway *gateway_;
  std::string channelName_;
  std::array<Contract<N>, N> contracts_;  

  std::array<Endpoint, N> endpoint_peers_;
};
} // namespace fabric

#endif // FABRIC_GATEWAY_NETWORK_H
