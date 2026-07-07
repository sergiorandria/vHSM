#ifndef FABRIC_GATEWAY_CONTRACT_H
#define FABRIC_GATEWAY_CONTRACT_H

#include "query.h"
#include <string>
#include <vector>
#include <memory>

namespace fabric {

class Network;

class Contract {
public:
    explicit Contract(const std::string& name_, Network* network = nullptr, const std::string& chaincodeName = "");
    ~Contract();
    Query& SubmitTransaction(const std::string& functionName, std::vector<std::string> args);
    Query& EvaluateTransaction(const std::string& functionName, std::vector<std::string> args);

private:
    std::string name_;
    std::string description_;
    Network* network_;
    std::string chaincodeName_;
    // To avoid copying
    Contract(const Contract&) = delete;
    Contract& operator=(const Contract&) = delete;
};

} // namespace fabric

#endif // FABRIC_GATEWAY_CONTRACT_H