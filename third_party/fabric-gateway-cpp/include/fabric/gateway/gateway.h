#ifndef FABRIC_GATEWAY_GATEWAY_H
#define FABRIC_GATEWAY_GATEWAY_H

#include <memory>
#include <string>

#include "fabric/grpc/grpc_connection.h"
#include "fabric/identity/identity.h"

#include "gateway/gateway.grpc.pb.h"

namespace fabric {
namespace gateway {

class Network;
class Contract;
class Transaction;

/**
 * High-level Fabric Gateway client. Wraps a GrpcConnection to a Fabric
 * Gateway peer and exposes the Evaluate / Endorse / Submit / CommitStatus
 * RPCs plus the Network → Contract → Transaction programming model.
 */
class Gateway : public std::enable_shared_from_this<Gateway> {
public:
    /**
     * Connect to a Fabric Gateway.
     * @param connection Established gRPC connection to the gateway peer
     * @param identity Identity used to sign proposals and transactions
     * @return Gateway client
     */
    static std::shared_ptr<Gateway> connect(
        std::shared_ptr<fabric::grpc::GrpcConnection> connection,
        const identity::Identity& identity);

    ~Gateway() = default;

    /**
     * Invoke the gateway Evaluate service (query a chaincode).
     * @param request Evaluate request carrying a signed proposal
     * @param response Filled on success
     * @return gRPC status
     */
    ::grpc::Status evaluate(const ::gateway::EvaluateRequest& request,
                          ::gateway::EvaluateResponse* response);

    /**
     * Invoke the gateway Endorse service, obtaining a prepared transaction.
     * @param request Endorse request carrying a signed proposal
     * @param response Filled on success
     * @return gRPC status
     */
    ::grpc::Status endorse(const ::gateway::EndorseRequest& request,
                         ::gateway::EndorseResponse* response);

    /**
     * Invoke the gateway Submit service with a signed prepared transaction.
     * @param request Submit request
     * @param response Filled on success
     * @return gRPC status
     */
    ::grpc::Status submit(const ::gateway::SubmitRequest& request,
                        ::gateway::SubmitResponse* response);

    /**
     * Invoke the gateway CommitStatus service to wait for commit.
     * @param request Signed commit status request
     * @param response Filled with the transaction validation result
     * @return gRPC status
     */
    ::grpc::Status commitStatus(const ::gateway::SignedCommitStatusRequest& request,
                              ::gateway::CommitStatusResponse* response);

    /**
     * Obtain the network (channel) abstraction for a channel.
     * @param channelId Channel name
     * @return Network handle
     */
    std::shared_ptr<Network> getNetwork(const std::string& channelId);

    const identity::Identity& identity() const { return identity_; }
    std::shared_ptr<fabric::grpc::GrpcConnection> connection() const {
        return connection_;
    }

private:
    Gateway(std::shared_ptr<fabric::grpc::GrpcConnection> connection,
            const identity::Identity& identity);

    std::shared_ptr<fabric::grpc::GrpcConnection> connection_;
    identity::Identity identity_;
    std::unique_ptr<::gateway::Gateway::Stub> stub_;
};

} // namespace gateway
} // namespace fabric

#endif // FABRIC_GATEWAY_GATEWAY_H