#ifndef FABRIC_CRYPTO_TLS_CONFIG_BUILDER_H
#define FABRIC_CRYPTO_TLS_CONFIG_BUILDER_H

namespace fabric::crypto { 
class TLSConfigBuilder { 
public: 
    // Should build tls config backend here
    void buildTlsConfigBackend(void* data); // undefined 
    
};
} // namespace fabric::crypto

#endif // FABRIC_CRYPTO_TLS_CONFIG_BUILDER_H