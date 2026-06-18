#include "../../../include/fabric/ca/httpclient.h"

#include <stdexcept>
#include <stdexcept>

namespace fabric {
namespace ca {

CurlHttpClient::CurlHttpClient() {
    curl_ = curl_easy_init();
    if (!curl_) {
        throw std::runtime_error("Failed to initialize CURL");
    }

    // Set default options
    curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl_, CURLOPT_HEADERFUNCTION, headerCallback);
    curl_easy_setopt(curl_, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl_, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl_, CURLOPT_TCP_KEEPALIVE, 1L);
}

CurlHttpClient::~CurlHttpClient() {
    if (headers_) {
        curl_slist_free_all(headers_);
    }
    if (curl_) {
        curl_easy_cleanup(curl_);
    }
}

size_t CurlHttpClient::writeCallback(char* ptr, size_t size, size_t nmemb, std::string* data) {
    size_t totalSize = size * nmemb;
    data->append(ptr, totalSize);
    return totalSize;
}

size_t CurlHttpClient::headerCallback(char* buffer, size_t size, size_t nitems, void* userdata) {
    size_t totalSize = size * nitems;
    std::string header(buffer, totalSize);

    // Parse header (format: "Key: Value")
    auto colonPos = header.find(':');
    if (colonPos != std::string::npos) {
        std::string key = header.substr(0, colonPos);
        std::string value = header.substr(colonPos + 1);
        // Trim whitespace
        key.erase(key.find_last_not_of(" \t\n\r\f\v") + 1);
        value.erase(0, value.find_first_not_of(" \t\n\r\f\v"));
        value.erase(value.find_last_not_of(" \t\n\r\f\v") + 1);

        auto* response = static_cast<std::vector<std::pair<std::string, std::string>>*>(userdata);
        response->emplace_back(std::move(key), std::move(value));
    }
    return totalSize;
}

HttpResponse CurlHttpClient::request(
    HttpMethod method,
    const std::string& url,
    const std::vector<std::pair<std::string, std::string>>& headers,
    const std::optional<std::string>& body,
    int timeoutSeconds) {

    HttpResponse response;
    std::string responseBody;
    std::vector<std::pair<std::string, std::string>> responseHeaders;

    // Reset headers list
    if (headers_) {
        curl_slist_free_all(headers_);
        headers_ = nullptr;
    }

    // Set URL
    curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());

    // Set timeout
    curl_easy_setopt(curl_, CURLOPT_TIMEOUT, timeoutSeconds);

    // Set write callback for body
    curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &responseBody);

    // Set header callback
    curl_easy_setopt(curl_, CURLOPT_HEADERDATA, &responseHeaders);

    // Set custom headers
    struct curl_slist* chunk = nullptr;
    for (const auto& [key, value] : headers) {
        std::string headerLine = key + ": " + value;
        chunk = curl_slist_append(chunk, headerLine.c_str());
    }
    if (chunk) {
        curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, chunk);
    }

    // Set HTTP method and body
    switch (method) {
        case HttpMethod::GET:
            curl_easy_setopt(curl_, CURLOPT_HTTPGET, 1L);
            break;
        case HttpMethod::POST:
            curl_easy_setopt(curl_, CURLOPT_POST, 1L);
            if (body.has_value()) {
                curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, body->c_str());
                curl_easy_setopt(curl_, CURLOPT_POSTFIELDSIZE, body->size());
            }
            break;
        case HttpMethod::PUT:
            curl_easy_setopt(curl_, CURLOPT_CUSTOMREQUEST, "PUT");
            if (body.has_value()) {
                curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, body->c_str());
                curl_easy_setopt(curl_, CURLOPT_POSTFIELDSIZE, body->size());
            }
            break;
        case HttpMethod::DELETE:
            curl_easy_setopt(curl_, CURLOPT_CUSTOMREQUEST, "DELETE");
            break;
    }

    // Perform request
    CURLcode res = curl_easy_perform(curl_);
    if (res != CURLE_OK) {
        throw std::runtime_error("CURL request failed: " + std::string(curl_easy_strerror(res)));
    }

    // Get response code
    long httpCode = 0;
    curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &httpCode);
    response.statusCode = static_cast<int>(httpCode);

    // Set response data
    response.body = std::move(responseBody);
    response.headers = std::move(responseHeaders);

    // Clean up headers
    if (chunk) {
        curl_slist_free_all(chunk);
    }

    return response;
}

void CurlHttpClient::setTLSOptions(
    const std::optional<std::string>& caCertPath,
    const std::optional<std::string>& certPath,
    const std::optional<std::string>& keyPath) {

    if (caCertPath.has_value()) {
        caCertPath_ = caCertPath.value();
        curl_easy_setopt(curl_, CURLOPT_CAINFO, caCertPath_.c_str());
        curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYHOST, 2L);
    } else {
        // If no CA cert provided, disable verification (not recommended for production)
        curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    if (certPath.has_value() && keyPath.has_value()) {
        certPath_ = certPath.value();
        keyPath_ = keyPath.value();
        curl_easy_setopt(curl_, CURLOPT_SSLCERT, certPath_.c_str());
        curl_easy_setopt(curl_, CURLOPT_SSLKEY, keyPath_.c_str());
    }
}

} // namespace ca
} // namespace fabric