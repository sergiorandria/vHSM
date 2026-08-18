#include "../../../include/fabric/grpc/grpc_status.h"

namespace fabric {
namespace grpc {

GrpcError::GrpcError(const std::string& what,
                     ::grpc::StatusCode code,
                     const std::string& grpcMessage,
                     const std::string& details)
    : std::runtime_error(what), code_(code), grpcMessage_(grpcMessage), details_(details) {}

ConnectionError::ConnectionError(const std::string& what)
    : GrpcError(what, ::grpc::StatusCode::UNAVAILABLE, "channel not ready", "") {}

StatusException::StatusException(::grpc::StatusCode code,
                                 const std::string& grpcMessage,
                                 const std::string& details)
    : GrpcError("RPC failed with status " + std::to_string(static_cast<int>(code)) +
                    " (" + statusCodeName(code) + "): " + grpcMessage +
                    (!details.empty() ? "; " + details : ""),
                code, grpcMessage, details) {}

const char* statusCodeName(::grpc::StatusCode code) {
    switch (code) {
        case ::grpc::StatusCode::OK: return "OK";
        case ::grpc::StatusCode::CANCELLED: return "CANCELLED";
        case ::grpc::StatusCode::UNKNOWN: return "UNKNOWN";
        case ::grpc::StatusCode::INVALID_ARGUMENT: return "INVALID_ARGUMENT";
        case ::grpc::StatusCode::DEADLINE_EXCEEDED: return "DEADLINE_EXCEEDED";
        case ::grpc::StatusCode::NOT_FOUND: return "NOT_FOUND";
        case ::grpc::StatusCode::ALREADY_EXISTS: return "ALREADY_EXISTS";
        case ::grpc::StatusCode::PERMISSION_DENIED: return "PERMISSION_DENIED";
        case ::grpc::StatusCode::RESOURCE_EXHAUSTED: return "RESOURCE_EXHAUSTED";
        case ::grpc::StatusCode::FAILED_PRECONDITION: return "FAILED_PRECONDITION";
        case ::grpc::StatusCode::ABORTED: return "ABORTED";
        case ::grpc::StatusCode::OUT_OF_RANGE: return "OUT_OF_RANGE";
        case ::grpc::StatusCode::UNIMPLEMENTED: return "UNIMPLEMENTED";
        case ::grpc::StatusCode::INTERNAL: return "INTERNAL";
        case ::grpc::StatusCode::UNAVAILABLE: return "UNAVAILABLE";
        case ::grpc::StatusCode::DATA_LOSS: return "DATA_LOSS";
        case ::grpc::StatusCode::UNAUTHENTICATED: return "UNAUTHENTICATED";
        default: return "UNKNOWN_STATUS";
    }
}

bool isRetryable(::grpc::StatusCode code) {
    // Transient transport/ordering failures are retryable; application-level
    // rejections are not.
    switch (code) {
        case ::grpc::StatusCode::UNAVAILABLE:
        case ::grpc::StatusCode::DEADLINE_EXCEEDED:
        case ::grpc::StatusCode::RESOURCE_EXHAUSTED:
        case ::grpc::StatusCode::ABORTED:
        case ::grpc::StatusCode::CANCELLED:
            return true;
        default:
            return false;
    }
}

} // namespace grpc
} // namespace fabric