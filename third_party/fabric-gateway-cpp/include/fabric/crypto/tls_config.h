#ifndef FABRIC_CRYPTO_TLS_CONFIG 
#define FABRIC_CRYPTO_TLS_CONFIG 

#include "tls_config_builder.h"

namespace fabric::crypto { 

class TLSConfig { 
public:
    void buildTLSConfig();     

private: 
    // TLS configuration backend
    TLSConfigBuilder builder;
};
} // fabric::crypto
#endif // FABRIC_CRYPTO_TLS_CONFIG