#ifndef FABRIC_CLIENT_TLS_CONFIG_H 
#define FABRIC_CLIENT_TLS_CONFIG_H

#include "x509.h"
#include "x509_pool.h"
#include "key_cert_files.h"


namespace fabric::crypto { 

struct ClienTLSConfig {
    bool enabled; 
    std::byte* certFiles; // A list of comma separated PEM-encoded trusted certificate bytes
    KeyCertFiles client; 
    x509::X509Pool<>* tlsCertPool;
};
} // namespace fabric::crypto

#endif // FABRIC_CLIENT_TLS_CONFIG_H