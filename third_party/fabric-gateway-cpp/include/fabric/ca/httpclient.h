#ifndef FABRIC_CA_HTTPCLIENT_H
#define FABRIC_CA_HTTPCLIENT_H

#include <curl/curl.h>
#include <string>
#include <vector>
#include <optional>
#include "httptypes.h"

namespace fabric {
namespace ca {

/**
 * libcurl implementation of HttpClient
 */
class CurlHttpClient : public HttpClient {
public:
    CurlHttpClient();
    ~CurlHttpClient() override;

    // Disable copy/move to avoid issues with CURL handles
    CurlHttpClient(const CurlHttpClient&) = delete;
    CurlHttpClient& operator=(const CurlHttpClient&) = delete;
    CurlHttpClient(CurlHttpClient&&) = delete;
    CurlHttpClient& operator=(CurlHttpClient&&) = delete;

    HttpResponse request(
        HttpMethod method,
        const std::string& url,
        const std::vector<std::pair<std::string, std::string>>& headers = {},
        const std::optional<std::string>& body = std::nullopt,
        int timeoutSeconds = 30) override;

    void setTLSOptions(
        const std::optional<std::string>& caCertPath = std::nullopt,
        const std::optional<std::string>& certPath = std::nullopt,
        const std::optional<std::string>& keyPath = std::nullopt) override;

private:
    static size_t writeCallback(char* ptr, size_t size, size_t nmemb, std::string* data);
    static size_t headerCallback(char* buffer, size_t size, size_t nitems, void* userdata);

    CURL* curl_;
    struct curl_slist* headers_ = nullptr;
    std::string caCertPath_;
    std::string certPath_;
    std::string keyPath_;
};

} // namespace ca
} // namespace fabric

#endif // FABRIC_CA_HTTPCLIENT_H