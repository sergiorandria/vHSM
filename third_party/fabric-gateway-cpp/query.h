#ifndef FABRIC_GATEWAY_QUERY_H 
#define FABRIC_GATEWAY_QUERY_H 

#include <string>

namespace fabric { 

class Query {
public: 
    Query();
    ~Query();

    std::string ToString();

    Query(const Query&) = default; 
    Query& operator=(const Query&) = default;
};
} // namespace fabric
#endif // FABRIC_GATEWAY_QUERY_H