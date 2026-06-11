/*
 * hsm_object.cpp
 *
 * Base implementation for all HSM keystore objects.
 * Sensitive objects are non-copyable; copy constructor and copy-assignment
 * throw if sensitive_ is true. Move operations are noexcept for container
 * compatibility. The destructor and wipe() zero all SecureBuffer members
 * before deallocation.
 */

#include "hsm_object.h"
#include "../core/error.h"

#include <stdexcept>

namespace vhsm::keystore {

HsmObject::HsmObject(ObjectType type, bool sensitive, bool extractable)
    : type_(type)
    , sensitive_(sensitive)
    , extractable_(extractable)
    , id_(0)  // empty, caller sets via setId() when needed
{}

HsmObject::~HsmObject() noexcept {
    wipe();
}

HsmObject::HsmObject(const HsmObject& other)
    : type_(other.type_)
    , sensitive_(other.sensitive_)
    , extractable_(other.extractable_)
    , id_(0)
{
    VHSM_CHECK_MSG(sensitive_, "HsmObject: copy of sensitive object is not permitted");

    if (other.id_.size() > 0) {
        id_ = SecureBuffer(other.id_.size());
        id_.write(0, other.id_.data(), other.id_.size());
    }
}

HsmObject& HsmObject::operator=(const HsmObject& other) {
    if (this == &other) return *this;

    if (sensitive_ || other.sensitive_) {
        throw std::runtime_error(
            "HsmObject: copy-assignment of sensitive object is not permitted");
    }

    wipe();

    type_        = other.type_;
    sensitive_   = other.sensitive_;
    extractable_ = other.extractable_;

    if (other.id_.size() > 0) {
        id_ = SecureBuffer(other.id_.size());
        id_.write(0, other.id_.data(), other.id_.size());
    } else {
        id_ = SecureBuffer(0);
    }

    return *this;
}

HsmObject::HsmObject(HsmObject&& other) noexcept
    : type_(other.type_)
    , sensitive_(other.sensitive_)
    , extractable_(other.extractable_)
    , id_(std::move(other.id_))
{
    other.type_        = ObjectType::OTHER;
    other.sensitive_   = false;
    other.extractable_ = false;
}

HsmObject& HsmObject::operator=(HsmObject&& other) noexcept {
    if (this == &other) return *this;

    wipe();

    type_        = other.type_;
    sensitive_   = other.sensitive_;
    extractable_ = other.extractable_;
    id_          = std::move(other.id_);

    other.type_        = ObjectType::OTHER;
    other.sensitive_   = false;
    other.extractable_ = false;

    return *this;
}

ObjectType HsmObject::getType() const noexcept {
    return type_;
}

bool HsmObject::isSensitive() const noexcept {
    return sensitive_;
}

bool HsmObject::isExtractable() const noexcept {
    return extractable_;
}

std::span<const u8> HsmObject::getId() const noexcept {
    if (id_.size() == 0) return {};
    return { id_.data(), id_.size() };
}

void HsmObject::setId(std::span<const u8> id) {
    if (id.empty()) {
        id_ = SecureBuffer(0);
        return;
    }

    id_ = SecureBuffer(id.size());
    id_.write(0, id.data(), id.size());
}

// Wipe — zeroes all sensitive fields; override in derived classes to also
// zero key material before the destructor chain reaches this base.
void HsmObject::wipe() noexcept {
    id_.wipe();
    sensitive_   = false;
    extractable_ = false;
}
} // namespace vhsm::keystore