#include "email_adapter.h"

#include <cstdlib>
#include <sstream>

namespace vhsm::notification {

namespace {

std::string env(const char* name, const char* fallback = "") {
    const char* v = std::getenv(name);
    return (v && *v) ? std::string(v) : std::string(fallback);
}

} // namespace

EmailAdapter::EmailAdapter(Sender sender) : sender_(std::move(sender)) {}

std::string EmailAdapter::render_message(const NotificationEvent& event,
                                         const std::string& from) {
    std::ostringstream out;
    out << "From: <" << from << ">\r\n"
        << "To: <subscriber>\r\n"
        << "Subject: [vHSM] " << event.summary << "\r\n"
        << "Date: " << event.timestamp << "\r\n"
        << "X-vHSM-Event-Type: " << static_cast<int>(event.type) << "\r\n"
        << "\r\n"
        << "type=" << static_cast<int>(event.type)
        << " severity=" << static_cast<int>(event.severity)
        << " timestamp=" << event.timestamp << "\r\n"
        << "source=" << event.source << "\r\n"
        << "actor=" << event.actor << "\r\n"
        << "summary=" << event.summary << "\r\n"
        << "detail=" << event.detail_json << "\r\n"
        << "hsm_instance=" << event.hsm_instance << "\r\n";
    return out.str();
}

bool EmailAdapter::deliver(const NotificationSubscriber& subscriber,
                           const NotificationEvent& event) {
    const std::string from = env("VHSM_SMTP_FROM", "vhsm@localhost");
    return sender_(subscriber.address, render_message(event, from));
}

EmailAdapter::Sender EmailAdapter::default_sender() {
    return [](const std::string& /*to*/, const std::string& /*message*/) {
        // REAL TRANSPORT SEAM: wire an SMTP client (libcurl's SMTP protocol or
        // a dedicated library) here.  Without VHSM_SMTP_SERVER configured we
        // fail closed so operators notice rather than silently dropping alerts.
        const std::string server = std::getenv("VHSM_SMTP_SERVER")
                                       ? std::getenv("VHSM_SMTP_SERVER") : "";
        if (server.empty()) {
            return false;
        }
        // TODO(future): libcurl smtp://{server}:{port} with AUTH + STARTTLS.
        (void)server;
        return false;
    };
}

}  // namespace vhsm::notification