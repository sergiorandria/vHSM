#ifndef FABRIC_GRPC_GRPC_CONNECTION_H
#define FABRIC_GRPC_GRPC_CONNECTION_H

#include <chrono>
#include <memory>
#include <string>

#include <grpcpp/channel.h>
#include <grpcpp/grpcpp.h>

#include "fabric/grpc/grpc_status.h"

namespace fabric {
namespace grpc {

/**
 * gRPC channel tuning knobs.  Zero-valued durations leave the library (or
 * server) defaults in place.
 */
struct ChannelOptions {
  // Keepalive: probes that detect dead peers.
  std::chrono::milliseconds keepAliveTime{5000};
  std::chrono::milliseconds keepAliveTimeout{2000};
  // Reconnect/backoff bounds.
  std::chrono::milliseconds minReconnectBackoff{0};
  std::chrono::milliseconds maxReconnectBackoff{0};
  // How long waitForReady() is willing to block.
  std::chrono::milliseconds waitForReadyTimeout{10000};
};

/**
 * TLS/mTLS material for connecting to a Fabric peer / gateway / orderer.
 */
struct TlsCredentials {
  // PEM bundle of root CAs used to verify the server.  Empty = system roots.
  std::string rootCert;
  // Optional client certificate + key for mutual TLS.
  std::string clientCert;
  std::string clientKey;
  // Grpc verifies the server name against the certificate unless overridden
  // here.  Test networks typically need this (IP-address endpoints).
  std::string serverNameOverride;

  bool isZero() const {
    return rootCert.empty() && clientCert.empty() && clientKey.empty() &&
           serverNameOverride.empty();
  }
};

/**
 * A gRPC channel to a Fabric peer / gateway / orderer with TLS or mTLS.
 * Connection is lazy (established on first RPC); use waitForReady() to block
 * until the channel is usable or raise ConnectionError on timeout.
 */
class GrpcConnection {
public:
  GrpcConnection(const GrpcConnection &) = delete;
  GrpcConnection &operator=(const GrpcConnection &) = delete;

  /**
   * Connect over TLS / mTLS using the supplied credentials.
   */
  static std::shared_ptr<GrpcConnection>
  connect(const std::string &target, const TlsCredentials &tls,
          const ChannelOptions &options = {});

  /**
   * Connect without transport security (local development only).
   */
  static std::shared_ptr<GrpcConnection>
  connectInsecure(const std::string &target,
                  const ChannelOptions &options = {});

  const std::shared_ptr<::grpc::Channel> &channel() const { return channel_; }
  const std::string &target() const { return target_; }

  /**
   * True when the channel is currently READY.
   */
  bool isReady() const;

  /**
   * Blocks up to ChannelOptions::waitForReadyTimeout for the channel to reach
   * READY, throwing ConnectionError on timeout.
   */
  void waitForReady() const;

private:
  GrpcConnection(std::shared_ptr<::grpc::Channel> channel, std::string target,
                 std::chrono::milliseconds waitForReadyTimeout);

  std::shared_ptr<::grpc::Channel> channel_;
  std::string target_;
  std::chrono::milliseconds waitForReadyTimeout_;
};

} // namespace grpc
} // namespace fabric

#endif // FABRIC_GRPC_GRPC_CONNECTION_H