#ifndef VHSM_NOTIFICATION_MOBILE_PUSH_ADAPTER_H
#define VHSM_NOTIFICATION_MOBILE_PUSH_ADAPTER_H

#include <functional>
#include <string>

#include "notification_adapter.h"

namespace vhsm::notification {

// MobilePushAdapter — FCM push for the vHSM Mobile app.
// Channel: "mobile_push" (also accepts "fcm"). Subscriber.address is the
// FCM device token (Expo push token or raw FCM token). Payload is the same
// JSON as webhook_adapter. Transport is libcurl POST to FCM HTTP v1.
// When VHSM_FCM_SERVER_KEY / FIREBASE_PROJECT_ID is not set it fails closed.
class MobilePushAdapter : public NotificationAdapter {
public:
  using Sender = std::function<bool(const std::string &fcm_token,
                                    const std::string &json_body,
                                    int &http_status)>;

  explicit MobilePushAdapter(Sender sender);
  bool deliver(const NotificationSubscriber &subscriber,
               const NotificationEvent &event) override;
  const char *channel_name() const override { return "mobile_push"; }

  // Real libcurl sender — POST https://fcm.googleapis.com/fcm/send
  // Header: Authorization: key=<FCM_SERVER_KEY>
  static Sender default_fcm_sender();
  // Expo push sender — POST https://exp.host/--/api/v2/push/send
  static Sender default_expo_sender();

private:
  Sender sender_;
};

} // namespace vhsm::notification

#endif // VHSM_NOTIFICATION_MOBILE_PUSH_ADAPTER_H
