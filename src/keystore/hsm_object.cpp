#include "hsm_object.h"

namespace vhsm::keystore {

HsmObject::HsmObject(ObjectType type, bool sensitive, bool extractable)
    : type_(type), sensitive_(sensitive), extractable_(extractable) {}

HsmObject::ObjectType HsmObject::getType() const {
    return type_;
}

bool HsmObject::isSensitive() const {
    return sensitive_;
}

bool HsmObject::isExtractable() const {
    return extractable_;
}

const std::vector<uint8_t>& HsmObject::getId() const {
    return id_;
}

void HsmObject::setId(const std::vector<uint8_t>& id) {
    id_ = id;
}

} // namespace vhsm::keystore