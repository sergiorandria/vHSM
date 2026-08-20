#ifndef FABRIC_GATEWAY_NETWORK_H
#define FABRIC_GATEWAY_NETWORK_H

#include <memory>
#include <string>

namespace fabric {
namespace gateway {

class Gateway;
class Contract;

/**
 * A Fabric channel as exposed by the Gateway client. Provides access to
 * the chaincode contracts deployed on the channel.
 */
class Network : public std::enable_shared_from_this<Network> {
public:
  /**
   * Get a contract deployed on this network.
   * @param chaincodeName Name of the chaincode
   * @return Contract handle
   */
  std::shared_ptr<Contract> getContract(const std::string &chaincodeName);

  const std::string &channelId() const { return channelId_; }

  /**
   * Get the Gateway client that owns this network.
   * @return Gateway handle
   */
  std::shared_ptr<Gateway> gateway();

private:
  friend class Gateway;
  Network(std::shared_ptr<Gateway> gateway, std::string channelId);

  std::shared_ptr<Gateway> gateway_;
  std::string channelId_;
};

} // namespace gateway
} // namespace fabric

#endif // FABRIC_GATEWAY_NETWORK_H