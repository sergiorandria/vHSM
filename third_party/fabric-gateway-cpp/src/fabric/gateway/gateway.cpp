#include "fabric/gateway/gateway.h"

#include <chrono>

#include "fabric/gateway/network.h"

namespace fabric {
namespace gateway {

namespace {

constexpr auto kDefaultCallTimeout = std::chrono::seconds(30);
constexpr auto kCommitStatusTimeout = std::chrono::seconds(60);

} // namespace

std::shared_ptr<Gateway> Gateway::connect(
    std::shared_ptr<fabric::grpc::GrpcConnection> connection,
    const identity::Identity& identity) {
    return std::shared_ptr<Gateway>(new Gateway(std::move(connection), identity));
}

Gateway::Gateway(std::shared_ptr<fabric::grpc::GrpcConnection> connection,
                 const identity::Identity& identity)
    : connection_(std::move(connection)), identity_(identity),
      stub_(::gateway::Gateway::NewStub(connection_->channel())) {}

::grpc::Status Gateway::evaluate(const ::gateway::EvaluateRequest& request,
                               ::gateway::EvaluateResponse* response) {
    ::grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + kDefaultCallTimeout);
    return stub_->Evaluate(&context, request, response);
}

::grpc::Status Gateway::endorse(const ::gateway::EndorseRequest& request,
                              ::gateway::EndorseResponse* response) {
    ::grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + kDefaultCallTimeout);
    return stub_->Endorse(&context, request, response);
}

::grpc::Status Gateway::submit(const ::gateway::SubmitRequest& request,
                             ::gateway::SubmitResponse* response) {
    ::grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + kDefaultCallTimeout);
    return stub_->Submit(&context, request, response);
}

::grpc::Status Gateway::commitStatus(const ::gateway::SignedCommitStatusRequest& request,
                                   ::gateway::CommitStatusResponse* response) {
    ::grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + kCommitStatusTimeout);
    return stub_->CommitStatus(&context, request, response);
}

std::shared_ptr<Network> Gateway::getNetwork(const std::string& channelId) {
    return std::shared_ptr<Network>(new Network(shared_from_this(), channelId));
}

} // namespace gateway
} // namespace fabric