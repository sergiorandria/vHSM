#ifndef VHSM_MISC_QUEUE_H
#define VHSM_MISC_QUEUE_H

#include <optional>
#include <vector> 

#include "../keystore/hsm_object.h"

using namespace vhsm::keystore;

namespace vhsm::misc {
class Queue { 
    
public:
    explicit Queue(const std::optional<std::vector<HsmObject>>& ); 

    virtual ~Queue();
    
    // In a very large scale application, synchronous operations 
    // can overload the CPU (on older systems). To prevent that, 
    // Using coroutine to limit appendable object. 
    // Return the last object ID.
    std::string push_back(const std::optional<HsmObject>& );

    std::string pop_back();

private: 
    HsmObject *obj;
};
} // namespace misc

#endif // VHSM_MISC_QUEUE_H