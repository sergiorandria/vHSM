#include "query.h"
#include <sstream>

#include <grpc++/grpc++.h>

namespace fabric {

Query::Query() = default;

Query::~Query() = default;

std::string Query::ToString() {
    std::stringstream ss;
    ss << "Query response";
    return ss.str();
}
} // namespace fabric