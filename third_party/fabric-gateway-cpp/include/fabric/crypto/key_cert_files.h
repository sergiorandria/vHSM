#ifndef FABRIC_CRYPTO_KEY_CERT_FILES 
#define FABRIC_CRYPTO_KEY_CERT_FILES

#include <cstddef>

namespace fabric::crypto { 
struct KeyCertFiles { 
    std::byte* keyFile; 
    std::byte* certFile; 
};
} // namespace fabric::crypto

#endif // FABRIC_CRYPTO_KEY_CERT_FILES