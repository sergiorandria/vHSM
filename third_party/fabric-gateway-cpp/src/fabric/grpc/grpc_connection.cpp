#include "../../../include/fabric/grpc/grpc_connection.h"

#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/support/channel_arguments.h>

namespace fabric {
namespace grpc {

namespace {

::grpc::ChannelArguments makeChannelArguments(const TlsCredentials& tls,
                                              const ChannelOptions& opts) {
    ::grpc::ChannelArguments args;
    if (!tls.serverNameOverride.empty()) {
        // Test networks connect to peers by IP/host that differs from the
        // hostname the certificate was issued for.
        args.SetSslTargetNameOverride(tls.serverNameOverride);
    }
    if (opts.keepAliveTime.count() > 0) {
        args.SetInt(GRPC_ARG_KEEPALIVE_TIME_MS, static_cast<int>(opts.keepAliveTime.count()));
    }
    if (opts.keepAliveTimeout.count() > 0) {
        args.SetInt(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, static_cast<int>(opts.keepAliveTimeout.count()));
    }
    if (opts.minReconnectBackoff.count() > 0) {
        args.SetInt(GRPC_ARG_MIN_RECONNECT_BACKOFF_MS, static_cast<int>(opts.minReconnectBackoff.count()));
    }
    if (opts.maxReconnectBackoff.count() > 0) {
        args.SetInt(GRPC_ARG_MAX_RECONNECT_BACKOFF_MS, static_cast<int>(opts.maxReconnectBackoff.count()));
    }
    return args;
}

} // namespace

GrpcConnection::GrpcConnection(std::shared_ptr<::grpc::Channel> channel,
                               std::string target,
                               std::chrono::milliseconds waitForReadyTimeout)
    : channel_(std::move(channel)), target_(std::move(target)),
      waitForReadyTimeout_(waitForReadyTimeout) {}

std::shared_ptr<GrpcConnection> GrpcConnection::connect(
    const std::string& target,
    const TlsCredentials& tls,
    const ChannelOptions& options) {
    ::grpc::SslCredentialsOptions sslOpts;
    sslOpts.pem_root_certs = tls.rootCert;
    sslOpts.pem_private_key = tls.clientKey;
    sslOpts.pem_cert_chain = tls.clientCert;
    auto creds = ::grpc::SslCredentials(sslOpts);

    auto channel = ::grpc::CreateCustomChannel(target, creds,
                                               makeChannelArguments(tls, options));
    return std::shared_ptr<GrpcConnection>(
        new GrpcConnection(std::move(channel), target, options.waitForReadyTimeout));
}

std::shared_ptr<GrpcConnection> GrpcConnection::connectInsecure(
    const std::string& target,
    const ChannelOptions& options) {
    TlsCredentials none;
    auto channel = ::grpc::CreateCustomChannel(target, ::grpc::InsecureChannelCredentials(),
                                               makeChannelArguments(none, options));
    return std::shared_ptr<GrpcConnection>(
        new GrpcConnection(std::move(channel), target, options.waitForReadyTimeout));
}

bool GrpcConnection::isReady() const {
    return channel_->GetState(true) == GRPC_CHANNEL_READY;
}

void GrpcConnection::waitForReady() const {
    auto deadline = std::chrono::system_clock::now() + waitForReadyTimeout_;
    if (channel_->WaitForConnected(deadline)) {
        return;
    }
    throw ConnectionError("gRPC channel to '" + target_ +
                          "' did not become ready within " +
                          std::to_string(waitForReadyTimeout_.count()) + " ms");
}

} // namespace grpc
} // namespace fabric