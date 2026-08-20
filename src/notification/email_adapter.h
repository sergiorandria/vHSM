#ifndef VHSM_NOTIFICATION_EMAIL_ADAPTER_H
#define VHSM_NOTIFICATION_EMAIL_ADAPTER_H

#include <functional>
#include <string>

#include "notification_adapter.h"

namespace vhsm::notification {

// Delivers notifications as email (RFC 5322 message via SMTP).  The SMTP
// transport is injected so tests never need a real mail server; the default
// transport talks to the SMTP relay configured via env vars:
//   VHSM_SMTP_SERVER / VHSM_SMTP_PORT / VHSM_SMTP_USER / VHSM_SMTP_PASS /
//   VHSM_SMTP_FROM
// A fully functional SMTP client is intentionally a thin seam here: wire e.g.
// libcurl's SMTP support or a real queue in the default sender.
class EmailAdapter : public NotificationAdapter {
public:
  // transport: to-address, rendered message → success.
  using Sender =
      std::function<bool(const std::string &to, const std::string &message)>;

  explicit EmailAdapter(Sender sender = default_sender());

  bool deliver(const NotificationSubscriber &subscriber,
               const NotificationEvent &event) override;
  const char *channel_name() const override { return "email"; }

  // Renders a plain-text RFC 5322-ish message for `event`.
  static std::string render_message(const NotificationEvent &event,
                                    const std::string &from);

  // Default transport (env-configured).  Without VHSM_SMTP_SERVER the
  // default sender reports failure so misconfiguration is loud, not silent.
  static Sender default_sender();

private:
  Sender sender_;
};

} // namespace vhsm::notification

#endif // VHSM_NOTIFICATION_EMAIL_ADAPTER_H