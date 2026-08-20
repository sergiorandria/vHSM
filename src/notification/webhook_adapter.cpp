#include "webhook_adapter.h"

#include <nlohmann/json.hpp>

#include <curl/curl.h>

#include <exception>

namespace vhsm::notification {

namespace {

// libcurl OPT write callback sink (discards response body, records nothing).
std::size_t ignore_write(char*, std::size_t size, std::size_t nmemb, void*) {
    return size * nmemb;
}

struct CurlGlobalGuard {
    CurlGlobalGuard() { curl_global_init(CURL_GLOBAL_DEFAULT); }
    ~CurlGlobalGuard() { curl_global_cleanup(); }
};

} // namespace

WebhookAdapter::WebhookAdapter(Sender sender) : sender_(std::move(sender)) {}

bool WebhookAdapter::deliver(const NotificationSubscriber& subscriber,
                             const NotificationEvent& event) {
    // Build the wire JSON (mirrors the plan's notification payload).
    nlohmann::json payload;
    payload["event_id"] = event.hsm_instance.empty() ? "local" : event.hsm_instance;
    payload["event_type"] = static_cast<int>(event.type);
    payload["severity"] = static_cast<int>(event.severity);
    payload["timestamp"] = event.timestamp;
    payload["source"] = event.source;
    payload["actor"] = event.actor;
    payload["summary"] = event.summary;
    try {
        payload["detail"] = nlohmann::json::parse(event.detail_json.empty()
                                                      ? "{}" : event.detail_json);
    } catch (const std::exception&) {
        // Malformed detail must not kill the dispatcher thread; degrade safely.
        payload["detail"] = event.detail_json;
    }
    payload["hsm_instance"] = event.hsm_instance;

    int http_status = 0;
    return sender_(subscriber.address, payload.dump(), http_status);
}

WebhookAdapter::Sender WebhookAdapter::default_libcurl_sender() {
    return [](const std::string& url, const std::string& body, int& http_status) {
        static CurlGlobalGuard guard;
        CURL* curl = curl_easy_init();
        if (!curl) {
            return false;
        }

        curl_slist* headers = curl_slist_append(nullptr, "Content-Type: application/json");
        if (!headers) {
            curl_easy_cleanup(curl);
            return false;
        }

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 0L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ignore_write);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

        CURLcode rc = curl_easy_perform(curl);
        long code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        http_status = static_cast<int>(code);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (rc != CURLE_OK) {
            return false;
        }
        // Any 2xx is treated as delivered; non-2xx implies delivery failed.
        return code >= 200 && code < 300;
    };
}

}  // namespace vhsm::notification