#ifndef FABRIC_CLIENT_CONFIG_H 
#define FABRIC_CLIENT_CONFIG_H

#include <string>

#define ClientTLSConfig int
#define EnrollmentRequest int
#define CSRInfo int
#define CryptoSuite int 

namespace api {
    using RegistrationRequest = int;
    using RevocationRequest  = int; 
    using GetCAInfoRequest = int; 
} // namespace gateway::api 

namespace log { 
    using LogLevel = int;
}

namespace gateway::config {
struct ClientConfig { 
    std::string URL;
    std::string MSPdir; 

    ClientTLSConfig TLS; //undefined
    EnrollmentRequest enrollment; //undefined 
    CSRInfo csr; // undefined 
    api::RegistrationRequest id; // undefined
    api::RevocationRequest revoke; // undefined 
    api::GetCAInfoRequest caInfo; //undefined 
    
    std::string caName; 
    CryptoSuite csp; 

    std::string serverName; 

    bool debug = false; 
    log::LogLevel logLevel;
};
} // namespace gateway::config
#endif // FABRIC_CLIENT_CONFIG_H 