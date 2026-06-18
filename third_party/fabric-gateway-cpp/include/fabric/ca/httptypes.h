#ifndef FABRIC_CA_HTTPTYPES_H
#define FABRIC_CA_HTTPTYPES_H

#include <string>
#include <vector>
#include <optional>
#include <chrono>

namespace fabric {
namespace ca {

/**
 * HTTP request method
 */
enum class HttpMethod {
    GET,
    POST,
    PUT,
    DELETE
};

/**
 * HTTP response
 */
struct HttpResponse {
    int statusCode;
    std::string body;
    std::vector<std::pair<std::string, std::string>> headers;
};

/**
 * HTTP client interface
 */
class HttpClient {
public:
    virtual ~HttpClient() = default;

    /**
     * Make an HTTP request
     * @param method HTTP method
     * @param url Target URL
     * @param headers Optional headers
     * @param body Optional request body
     * @param timeoutSeconds Request timeout in seconds
     * @return HTTP response
     */
    virtual HttpResponse request(
        HttpMethod method,
        const std::string& url,
        const std::vector<std::pair<std::string, std::string>>& headers = {},
        const std::optional<std::string>& body = std::nullopt,
        int timeoutSeconds = 30) = 0;

    /**
     * Set SSL/TLS options for secure connections
     * @param caCertPath Path to CA certificate file for verification
     * @param certPath Path to client certificate file (for mTLS)
     * @param keyPath Path to client private key file (for mTLS)
     */
    virtual void setTLSOptions(
        const std::optional<std::string>& caCertPath = std::nullopt,
        const std::optional<std::string>& certPath = std::nullopt,
        const std::optional<std::string>& keyPath = std::nullopt) = 0;
};

} // namespace ca
} // namespace fabric

#endif // FABRIC_CA_HTTPTYPES_H