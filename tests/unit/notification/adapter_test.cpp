// adapter_test.cpp — Unit tests for the notification adapters (email,
// webhook, grpc_push) using injected mock transports.  The adapters render the
// wire payload and delegate delivery to an injectable Sender, so these tests
// validate rendering, error propagation and channel naming without any real
// SMTP / HTTP / gRPC endpoint.

#include <gtest/gtest.h>

#include <string>

#include "email_adapter.h"
#include "grpc_push_adapter.h"
#include "notification_event.h"
#include "notification_subscriber.h"
#include "webhook_adapter.h"

#include <nlohmann/json.hpp>

using vhsm::notification::EmailAdapter;
using vhsm::notification::GrpcPushAdapter;
using vhsm::notification::NotificationEvent;
using vhsm::notification::NotificationSubscriber;
using vhsm::notification::WebhookAdapter;

namespace {

NotificationEvent make_event(const char *summary = "test event") {
  NotificationEvent e;
  e.type = NotificationEvent::EventType::SIGN_CREATED;
  e.severity = NotificationEvent::Severity::INFO;
  e.timestamp = 1234567890;
  e.source = "signature_store";
  e.actor = "alice";
  e.summary = summary;
  e.detail_json = R"({"signature_id":"abc123"})";
  e.hsm_instance = "hsm-1";
  return e;
}

NotificationSubscriber make_subscriber(const char *channel,
                                       const char *address) {
  NotificationSubscriber s;
  s.id = "sub-1";
  s.name = "Alice";
  s.channel = channel;
  s.address = address;
  s.min_severity = "INFO";
  s.enabled = true;
  return s;
}

// ---------------------------------------------------------------------------
// EmailAdapter
// ---------------------------------------------------------------------------

TEST(EmailAdapterTest, ChannelNameIsEmail) {
  EmailAdapter adapter;
  EXPECT_STREQ(adapter.channel_name(), "email");
}

TEST(EmailAdapterTest, DeliversViaInjectedSender) {
  std::string delivered_to;
  std::string delivered_msg;
  EmailAdapter::Sender spy = [&](const std::string &to,
                                 const std::string &message) {
    delivered_to = to;
    delivered_msg = message;
    return true;
  };

  EmailAdapter adapter(spy);
  const auto sub = make_subscriber("email", "alice@example.com");
  EXPECT_TRUE(adapter.deliver(sub, make_event()));
  EXPECT_EQ(delivered_to, "alice@example.com");
  EXPECT_NE(delivered_msg.find("hsm-1"), std::string::npos);
}

TEST(EmailAdapterTest, PropagatesSenderFailure) {
  EmailAdapter::Sender always_fail = [](const std::string &,
                                        const std::string &) { return false; };
  EmailAdapter adapter(always_fail);
  const auto sub = make_subscriber("email", "bad@example.com");
  EXPECT_FALSE(adapter.deliver(sub, make_event()));
}

TEST(EmailAdapterTest, RenderMessageIncludesEventFields) {
  const std::string msg =
      EmailAdapter::render_message(make_event(), "noreply@vhsm.local");
  EXPECT_NE(msg.find("test event"), std::string::npos);
  EXPECT_NE(msg.find("noreply@vhsm.local"), std::string::npos);
  EXPECT_NE(msg.find("source=signature_store"), std::string::npos);
  EXPECT_NE(msg.find("hsm_instance=hsm-1"), std::string::npos);
}

// ---------------------------------------------------------------------------
// WebhookAdapter
// ---------------------------------------------------------------------------

TEST(WebhookAdapterTest, ChannelNameIsWebhook) {
  WebhookAdapter adapter;
  EXPECT_STREQ(adapter.channel_name(), "webhook");
}

TEST(WebhookAdapterTest, DeliversJsonPayloadWithEventFields) {
  std::string delivered_url;
  std::string delivered_body;
  WebhookAdapter::Sender spy = [&](const std::string &url,
                                   const std::string &body, int &status) {
    delivered_url = url;
    delivered_body = body;
    status = 200;
    return true;
  };

  WebhookAdapter adapter(spy);
  const auto sub = make_subscriber("webhook", "https://hooks.example.com/vhsm");
  EXPECT_TRUE(adapter.deliver(sub, make_event()));
  EXPECT_EQ(delivered_url, "https://hooks.example.com/vhsm");

  const auto json = nlohmann::json::parse(delivered_body);
  EXPECT_EQ(json["source"], "signature_store");
  EXPECT_EQ(json["summary"], "test event");
  EXPECT_EQ(json["detail"]["signature_id"], "abc123");
  EXPECT_EQ(json["hsm_instance"], "hsm-1");
}

TEST(WebhookAdapterTest, Non2xxStatusIsFailure) {
  WebhookAdapter::Sender reject = [](const std::string &, const std::string &,
                                     int &status) {
    status = 500;
    return false;
  };
  WebhookAdapter adapter(reject);
  const auto sub = make_subscriber("webhook", "https://hooks.example.com/bad");
  EXPECT_FALSE(adapter.deliver(sub, make_event()));
}

TEST(WebhookAdapterTest, MalformedDetailDegradesNotThrows) {
  WebhookAdapter::Sender spy = [](const std::string &, const std::string &,
                                  int &status) {
    status = 202;
    return true;
  };
  WebhookAdapter adapter(spy);

  auto ev = make_event();
  ev.detail_json = "not-json{";
  const auto sub = make_subscriber("webhook", "https://hooks.example.com/x");
  // Must deliver successfully even though detail_json is malformed.
  EXPECT_TRUE(adapter.deliver(sub, ev));
}

// ---------------------------------------------------------------------------
// GrpcPushAdapter
// ---------------------------------------------------------------------------

TEST(GrpcPushAdapterTest, ChannelNameIsGrpcPush) {
  GrpcPushAdapter adapter;
  EXPECT_STREQ(adapter.channel_name(), "grpc_push");
}

TEST(GrpcPushAdapterTest, DeliversToAddressViaInjectedSender) {
  std::string delivered_address;
  std::string delivered_payload;
  GrpcPushAdapter::Sender spy = [&](const std::string &address,
                                    const std::string &payload) {
    delivered_address = address;
    delivered_payload = payload;
    return true;
  };

  GrpcPushAdapter adapter(spy);
  const auto sub = make_subscriber("grpc_push", "push://siem:50051");
  EXPECT_TRUE(adapter.deliver(sub, make_event()));
  EXPECT_EQ(delivered_address, "push://siem:50051");
  EXPECT_NE(delivered_payload.find("test event"), std::string::npos);
}

TEST(GrpcPushAdapterTest, RenderPayloadIsValidJson) {
  const std::string payload = GrpcPushAdapter::render_payload(make_event());
  const auto json = nlohmann::json::parse(payload);
  EXPECT_EQ(json["source"], "signature_store");
}

} // namespace