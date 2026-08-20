#include "grpc_push_adapter.h"

#include <nlohmann/json.hpp>

#include <exception>

namespace vhsm::notification {

GrpcPushAdapter::GrpcPushAdapter(Sender sender) : sender_(std::move(sender)) {}

std::string GrpcPushAdapter::render_payload(const NotificationEvent &event) {
  nlohmann::json payload;
  payload["event_type"] = static_cast<int>(event.type);
  payload["severity"] = static_cast<int>(event.severity);
  payload["timestamp"] = event.timestamp;
  payload["source"] = event.source;
  payload["actor"] = event.actor;
  payload["summary"] = event.summary;
  try {
    payload["detail"] = nlohmann::json::parse(
        event.detail_json.empty() ? "{}" : event.detail_json);
  } catch (const std::exception &) {
    payload["detail"] = event.detail_json;
  }
  payload["hsm_instance"] = event.hsm_instance;
  return payload.dump();
}

bool GrpcPushAdapter::deliver(const NotificationSubscriber &subscriber,
                              const NotificationEvent &event) {
  return sender_(subscriber.address, render_payload(event));
}

GrpcPushAdapter::Sender GrpcPushAdapter::default_sender() {
  return [](const std::string & /*address*/, const std::string & /*payload*/) {
    // REAL TRANSPORT SEAM: wire a generated gRPC push client here.
    // Fail closed — silent drops of SIEM events are worse than none.
    return false;
  };
}

} // namespace vhsm::notification