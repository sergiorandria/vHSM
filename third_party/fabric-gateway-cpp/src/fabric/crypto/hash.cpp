#include "fabric/crypto/hash.h"

#include <openssl/evp.h>
#include <stdexcept>

namespace fabric {
namespace crypto {

std::string sha256(const std::string& data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create digest context");
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
              EVP_DigestUpdate(ctx, data.data(), data.size()) == 1 &&
              EVP_DigestFinal_ex(ctx, digest, &digestLen) == 1;
    EVP_MD_CTX_free(ctx);

    if (!ok) {
        throw std::runtime_error("Failed to compute SHA-256");
    }
    return std::string(reinterpret_cast<char*>(digest), digestLen);
}

} // namespace crypto
} // namespace fabric