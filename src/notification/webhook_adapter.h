#ifndef VHSM_NOTIFICATION_WEBHOOK_ADAPTER_H
#define VHSM_NOTIFICATION_WEBHOOK_ADAPTER_H

#include <functional>
#include <string>

#include "notification_adapter.h"

namespace vhsm::notification {

// Delivers notifications as HTTP(S) POSTs to the subscriber's webhook URL.
// The default transport uses libcurl; tests inject a mock transport so no
// network is required.
class WebhookAdapter : public NotificationAdapter {
public:
  // transport: url, JSON body → success, HTTP status code.
  using Sender = std::function<bool(const std::string &url,
                                    const std::string &body, int &http_status)>;

  explicit WebhookAdapter(Sender sender = default_libcurl_sender());

  bool deliver(const NotificationSubscriber &subscriber,
               const NotificationEvent &event) override;
  const char *channel_name() const override { return "webhook"; }

  // Real HTTP(S) POST via libcurl.  Uses system CA trust; set
  // CURLOPT_SSL_VERIFYPEER via the CA env vars in the libcurl setup.
  static Sender default_libcurl_sender();

private:
  Sender sender_;
};

} // namespace vhsm::notification

#endif // VHSM_NOTIFICATION_WEBHOOK_ADAPTER_H