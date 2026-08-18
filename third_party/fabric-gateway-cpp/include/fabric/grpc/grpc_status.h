#ifndef FABRIC_GRPC_GRPC_STATUS_H
#define FABRIC_GRPC_GRPC_STATUS_H

#include <grpcpp/grpcpp.h>
#include <stdexcept>
#include <string>

namespace fabric {
namespace grpc {

/**
 * Base exception carrying an underlying gRPC status.
 */
class GrpcError : public std::runtime_error {
public:
    GrpcError(const std::string& what,
              ::grpc::StatusCode code = ::grpc::StatusCode::UNKNOWN,
              const std::string& grpcMessage = "",
              const std::string& details = "");

    ::grpc::StatusCode code() const noexcept { return code_; }
    const std::string& grpcMessage() const noexcept { return grpcMessage_; }
    const std::string& details() const noexcept { return details_; }

private:
    ::grpc::StatusCode code_;
    std::string grpcMessage_;
    std::string details_;
};

/**
 * Raised when a gRPC channel cannot be established or is not usable.
 */
class ConnectionError : public GrpcError {
public:
    explicit ConnectionError(const std::string& what);
};

/**
 * Raised when an RPC completes with a non-OK gRPC status.
 */
class StatusException : public GrpcError {
public:
    StatusException(::grpc::StatusCode code,
                    const std::string& grpcMessage,
                    const std::string& details = "");
};

/**
 * Human-readable label for a gRPC status code.
 */
const char* statusCodeName(::grpc::StatusCode code);

/**
 * Whether a failed RPC with this status code is worth retrying
 * (used by the Phase 4 transaction retry policy).
 */
bool isRetryable(::grpc::StatusCode code);

} // namespace grpc
} // namespace fabric

#endif // FABRIC_GRPC_GRPC_STATUS_H