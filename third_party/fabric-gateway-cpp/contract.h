#ifndef FABRIC_GATEWAY_CONTRACT_H
#define FABRIC_GATEWAY_CONTRACT_H

#include "gateway.h"
#include "query.h"
#include <vector>

namespace fabric { 

class Contract { 
public: 
    explicit Contract(const std::string& name_); 

    // Return The transaction ID
    Query& SubmitTransaction(const std::string&, std::vector<std::string>);
    Query& EvaluateTransaction(const std::string&, std::vector<std::string>);

private: 
    std::string name_; 
    std::string description_;
};
} // namespace fabric
#endif // FABRIC_GATEWAY_CONTRACT_H