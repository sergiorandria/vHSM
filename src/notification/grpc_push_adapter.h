#ifndef VHSM_NOTIFICATION_GRPC_PUSH_ADAPTER_H
#define VHSM_NOTIFICATION_GRPC_PUSH_ADAPTER_H

#include <functional>
#include <string>

#include "notification_adapter.h"

namespace vhsm::notification {

// Delivers notifications via a gRPC push endpoint (used by SIEM / monitoring
// clients).  The wire format is a JSON object; the actual gRPC call is behind
// an injectable transport so tests and the v1 seal are clean.  Production
// wires this to a generated protobuf client for the push service.
class GrpcPushAdapter : public NotificationAdapter {
public:
    // transport: push-endpoint address, JSON payload → success.
    using Sender = std::function<bool(const std::string& address,
                                      const std::string& payload)>;

    explicit GrpcPushAdapter(Sender sender = default_sender());

    bool deliver(const NotificationSubscriber& subscriber,
                 const NotificationEvent& event) override;
    const char* channel_name() const override { return "grpc_push"; }

    // Renders the JSON payload for a gRPC push.
    static std::string render_payload(const NotificationEvent& event);

    // Default transport: fail closed until a gRPC push client is wired.
    static Sender default_sender();

private:
    Sender sender_;
};

}  // namespace vhsm::notification

#endif // VHSM_NOTIFICATION_GRPC_PUSH_ADAPTER_H