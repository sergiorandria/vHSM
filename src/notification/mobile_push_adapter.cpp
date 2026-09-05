#include "mobile_push_adapter.h"

#include <cstdlib>
#include <nlohmann/json.hpp>
#include <curl/curl.h>

namespace vhsm::notification {

namespace {

std::size_t ignore_write(char *, std::size_t size, std::size_t nmemb, void *) {
  return size * nmemb;
}

struct CurlGuard {
  CurlGuard() { curl_global_init(CURL_GLOBAL_DEFAULT); }
  ~CurlGuard() { curl_global_cleanup(); }
};

std::string build_payload(const NotificationEvent &event) {
  nlohmann::json p;
  p["event_type"] = static_cast<int>(event.type);
  p["severity"]   = static_cast<int>(event.severity);
  p["timestamp"]  = event.timestamp;
  p["source"]     = event.source;
  p["actor"]      = event.actor;
  p["summary"]    = event.summary;
  try {
    p["detail"] = nlohmann::json::parse(event.detail_json.empty() ? "{}" : event.detail_json);
  } catch (...) {
    p["detail"] = event.detail_json;
  }
  p["hsm_instance"] = event.hsm_instance;
  // FCM notification block for system tray
  nlohmann::json notif;
  notif["title"] = event.summary.substr(0, 60);
  notif["body"]  = event.actor + " • " + event.source;
  p["_notification"] = notif;
  return p.dump();
}

} // namespace

MobilePushAdapter::MobilePushAdapter(Sender sender) : sender_(std::move(sender)) {}

bool MobilePushAdapter::deliver(const NotificationSubscriber &subscriber,
                                const NotificationEvent &event) {
  if (subscriber.address.empty()) return false;
  std::string body = build_payload(event);
  int status = 0;
  return sender_(subscriber.address, body, status);
}

MobilePushAdapter::Sender MobilePushAdapter::default_fcm_sender() {
  return [](const std::string &token, const std::string &body, int &http_status) {
    const char *key = std::getenv("FCM_SERVER_KEY");
    if (!key || !*key) {
      // Also try Firebase project-based key
      key = std::getenv("FIREBASE_SERVER_KEY");
      if (!key || !*key) return false;
    }
    static CurlGuard guard;
    CURL *curl = curl_easy_init();
    if (!curl) return false;
    std::string auth = std::string("Authorization: key=") + key;
    curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, auth.c_str());

    // FCM legacy API expects {to: token, notification: {...}, data: {...}}
    nlohmann::json raw = nlohmann::json::parse(body);
    nlohmann::json fcm;
    fcm["to"] = token;
    fcm["notification"] = raw.value("_notification", nlohmann::json::object());
    fcm["data"] = raw;
    fcm["priority"] = "high";
    std::string fcm_body = fcm.dump();

    curl_easy_setopt(curl, CURLOPT_URL, "https://fcm.googleapis.com/fcm/send");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, fcm_body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)fcm_body.size());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ignore_write);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode rc = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    http_status = (int)code;
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK) return false;
    return code >= 200 && code < 300;
  };
}

MobilePushAdapter::Sender MobilePushAdapter::default_expo_sender() {
  return [](const std::string &token, const std::string &body, int &http_status) {
    // Expo push — token is ExponentPushToken[xxxx]
    if (token.rfind("ExponentPushToken", 0) != 0) {
      // Not an Expo token, fallback to FCM sender
      return MobilePushAdapter::default_fcm_sender()(token, body, http_status);
    }
    static CurlGuard guard;
    CURL *curl = curl_easy_init();
    if (!curl) return false;
    nlohmann::json raw = nlohmann::json::parse(body);
    nlohmann::json expo;
    expo["to"] = token;
    expo["title"] = raw.value("summary", "vHSM");
    expo["body"] = raw.value("source", "") + std::string(" • ") + raw.value("actor", "");
    expo["data"] = raw;
    expo["priority"] = "high";
    expo["channelId"] = "vhsm-default";
    std::string expo_body = expo.dump();

    curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, "https://exp.host/--/api/v2/push/send");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, expo_body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)expo_body.size());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ignore_write);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode rc = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    http_status = (int)code;
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return rc == CURLE_OK && code >= 200 && code < 300;
  };
}

} // namespace vhsm::notification
