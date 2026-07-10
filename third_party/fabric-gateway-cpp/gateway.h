#ifndef FABRIC_GATEWAY_GATEWAY_H
#define FABRIC_GATEWAY_GATEWAY_H

#include "contract.h"
#include <curl/curl.h>
#include <memory>
#include <string>

namespace fabric {

template <class T, std::size_t U> class Network<T, U>;

template <typename T>
concept EndpoitHasRequiredField = requires(T &&item) {
  item.isCertificateValid();
  assert(item.getOrgMSP() != nullptr);
};
// This interface should
// acts as a pass thru to the chaincode
class Gateway {

  using GatewayCreadentialsPtr = void *;

public:
  // Create new gateway connection
  static Gateway *Create(const std::string &endpoint,
                         GatewayCreadentialsPtr credentials);
  virtual ~Gateway();

  template <typename _EndpointTypeDefault, std::size_t PeersNum>
    requires EndpoitHasRequiredField<_EndpointTypeDefault>
  Network<_EndpointTypeDefault, int> *
  GetNetwork(const std::string &channelName);
  void Shutdown();

private:
  Gateway(const std::string &endpoint, void *credentials);
  std::string endpoint_;
  GatewayCreadentialsPtr credentials_;

  // We'll keep a CURL handle for convenience, but we can also create per
  // request.
  CURL *curl_;

  // To avoid copying
  Gateway(const Gateway &) = delete;
  Gateway &operator=(const Gateway &) = delete;
};
} // namespace fabric

#endif // FABRIC_GATEWAY_GATEWAY_H
