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

HsmObject::HsmObject(ObjectType type, bool sensitive, bool extractable,
                     bool token, bool priv)
    : type_(type)
    , sensitive_(sensitive)
    , extractable_(extractable)
    , token_(token)
    , private_(priv)
    , id_()
    , idSet_(false)
    , attrs_()
{}

HsmObject::~HsmObject() noexcept {
    wipe();
}

HsmObject::HsmObject(const HsmObject& other)
    : type_(other.type_)
    , sensitive_(other.sensitive_)
    , extractable_(other.extractable_)
    , token_(other.token_)
    , private_(other.private_)
    , idSet_(false)
    , attrs_(other.attrs_)
{
    VHSM_CHECK_MSG(!sensitive_, "HsmObject: copy of sensitive object is not permitted");

    if (other.idSet_ && other.id_.size() > 0) {
        id_ = SecureBuffer(other.id_.size());
        id_.write(0, other.id_.data(), other.id_.size());
        idSet_ = true;
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
    token_       = other.token_;
    private_     = other.private_;
    attrs_       = other.attrs_;

    if (other.idSet_ && other.id_.size() > 0) {
        id_ = SecureBuffer(other.id_.size());
        id_.write(0, other.id_.data(), other.id_.size());
        idSet_ = true;
    } else {
        id_ = SecureBuffer{};
        idSet_ = false;
    }

    return *this;
}

HsmObject::HsmObject(HsmObject&& other) noexcept
    : type_(other.type_)
    , sensitive_(other.sensitive_)
    , extractable_(other.extractable_)
    , token_(other.token_)
    , private_(other.private_)
    , id_(std::move(other.id_))
    , idSet_(other.idSet_)
    , attrs_(std::move(other.attrs_))
{
    other.type_        = ObjectType::OTHER;
    other.sensitive_   = false;
    other.extractable_ = false;
    other.token_       = false;
    other.private_     = false;
    other.idSet_       = false;
}

HsmObject& HsmObject::operator=(HsmObject&& other) noexcept {
    if (this == &other) return *this;

    wipe();

    type_        = other.type_;
    idSet_       = other.idSet_;
    sensitive_   = other.sensitive_;
    extractable_ = other.extractable_;
    token_       = other.token_;
    private_     = other.private_;
    id_          = std::move(other.id_);
    attrs_       = std::move(other.attrs_);

    other.type_        = ObjectType::OTHER;
    other.sensitive_   = false;
    other.extractable_ = false;
    other.token_       = false;
    other.private_     = false;
    other.idSet_       = false;

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

bool HsmObject::isToken() const noexcept {
    return token_;
}

bool HsmObject::isPrivate() const noexcept {
    return private_;
}

const std::vector<u8>* HsmObject::findAttribute(CK_ATTRIBUTE_TYPE type) const noexcept {
    auto it = attrs_.find(type);
    if (it == attrs_.end()) {
        return nullptr;
    }
    return &it->second;
}

void HsmObject::setAttribute(CK_ATTRIBUTE_TYPE type, const u8* data, std::size_t len) {
    if (len > 0 && data == nullptr) {
        throw std::invalid_argument("HsmObject::setAttribute: null data with non-zero length");
    }
    if (len == 0) {
        attrs_[type].clear();
        return;
    }
    attrs_[type].assign(data, data + len);
}

std::span<const u8> HsmObject::getId() const noexcept {
    if (!idSet_) return {};
    return { id_.data(), id_.size() };
}

void HsmObject::setId(std::span<const u8> id) {
    if (id.empty()) {
        id_ = SecureBuffer{};
        idSet_ = false;
        return;
    }

    id_ = SecureBuffer(id.size());
    idSet_ = true;
    id_.write(0, id.data(), id.size());
}

// Wipe — zeroes all sensitive fields; override in derived classes to also
// zero key material before the destructor chain reaches this base.
void HsmObject::wipe() noexcept {
    id_.wipe();
    for (auto& [type, value] : attrs_) {
        (void)type;
        if (!value.empty()) {
            volatile unsigned char* p = value.data();
            for (std::size_t i = 0; i < value.size(); ++i) {
                p[i] = 0;
            }
        }
    }
    attrs_.clear();
    idSet_       = false;
    sensitive_   = false;
    extractable_ = false;
    token_       = false;
    private_     = false;
}
} // namespace vhsm::keystore