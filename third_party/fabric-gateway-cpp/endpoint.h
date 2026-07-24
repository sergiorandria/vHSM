#ifndef FABRIC_SDK_ENDPOINT_H 
#define FABRIC_SDK_ENDPOINT_H 

#include <vector> 
#include "contract.h"

namespace network 
{ 
class Endpoint { 
public: 
#ifdef USE_EXPLICIT_CONSTRUCTOR
    explicit Endpoint(
        std::string uuid, // should be generated privately, using prng
        Contract allowedContract[],
        size_t allowContractSize = 1 
    ) {     

    }
#else 
    Endpoint(     
        std::string uuid, // should be generated privately, using prng
        fabric::Contract allowedContract[],
        size_t allowContractSize = 1 ) { 
        
    } 
#endif // USE_EXPLICIT_CONSTRUCTOR
private: 
    std::vector<fabric::Contract> allowedContract_;  
};
} // namespace network 


#endif // FABRIC_SDK_ENDPOINT_H