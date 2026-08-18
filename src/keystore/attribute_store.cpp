#include "attribute_store.h"

#include <cstring>

namespace vhsm::keystore {

namespace {
// PKCS#11: the "attribute length is unknown/unavailable" marker.
constexpr CK_ULONG CK_UNAVAILABLE_INFORMATION = static_cast<CK_ULONG>(~0UL);
} // namespace

AttributeStore::AttributeStore(HsmObject& object) : object_(object) {}

CK_RV AttributeStore::getAttribute(CK_ATTRIBUTE_TYPE type, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen) {
    if (pulValueLen == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }

    // Buffer that will hold a serialized copy of the attribute so the
    // size-probe / copy-out two phase protocol can use a single code path.
    std::vector<u8> value;
    bool known = false;

    switch (type) {
        case CKA_CLASS: {
            CK_ULONG classValue = 0;
            switch (object_.getType()) {
                case ObjectType::DATA: classValue = CKO_DATA; break;
                case ObjectType::CERTIFICATE: classValue = CKO_CERTIFICATE; break;
                case ObjectType::PUBLIC_KEY: classValue = CKO_PUBLIC_KEY; break;
                case ObjectType::PRIVATE_KEY: classValue = CKO_PRIVATE_KEY; break;
                case ObjectType::SECRET_KEY: classValue = CKO_SECRET_KEY; break;
                case ObjectType::HARDWARE_FEATURE: classValue = CKO_HW_FEATURE; break;
                case ObjectType::DOMAIN_PARAMETERS: classValue = CKO_DOMAIN_PARAMETERS; break;
                case ObjectType::OTHER: classValue = CKO_OTHER; break;
            }
            value.resize(sizeof(CK_ULONG));
            std::memcpy(value.data(), &classValue, sizeof(CK_ULONG));
            known = true;
            break;
        }
        case CKA_TOKEN: {
            CK_BBOOL v = object_.isToken() ? CK_TRUE : CK_FALSE;
            value.resize(sizeof(CK_BBOOL));
            std::memcpy(value.data(), &v, sizeof(CK_BBOOL));
            known = true;
            break;
        }
        case CKA_PRIVATE: {
            CK_BBOOL v = object_.isPrivate() ? CK_TRUE : CK_FALSE;
            value.resize(sizeof(CK_BBOOL));
            std::memcpy(value.data(), &v, sizeof(CK_BBOOL));
            known = true;
            break;
        }
        case CKA_SENSITIVE: {
            CK_BBOOL v = object_.isSensitive() ? CK_TRUE : CK_FALSE;
            value.resize(sizeof(CK_BBOOL));
            std::memcpy(value.data(), &v, sizeof(CK_BBOOL));
            known = true;
            break;
        }
        case CKA_EXTRACTABLE: {
            CK_BBOOL v = object_.isExtractable() ? CK_TRUE : CK_FALSE;
            value.resize(sizeof(CK_BBOOL));
            std::memcpy(value.data(), &v, sizeof(CK_BBOOL));
            known = true;
            break;
        }
        case CKA_ID: {
            auto idSpan = object_.getId();
            value.assign(idSpan.begin(), idSpan.end());
            known = true;
            break;
        }
        case CKA_VALUE:
            if (object_.isSensitive()) {
                *pulValueLen = CK_UNAVAILABLE_INFORMATION;
                return CKR_ATTRIBUTE_SENSITIVE;
            }
            [[fallthrough]];
        default: {
            const std::vector<u8>* stored = object_.findAttribute(type);
            if (stored != nullptr) {
                value = *stored;
                known = true;
            }
            break;
        }
    }

    if (!known) {
        *pulValueLen = CK_UNAVAILABLE_INFORMATION;
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }

    if (pValue == nullptr) {
        *pulValueLen = static_cast<CK_ULONG>(value.size());
        return CKR_OK;
    }

    if (*pulValueLen < value.size()) {
        *pulValueLen = static_cast<CK_ULONG>(value.size());
        return CKR_BUFFER_TOO_SMALL;
    }

    if (!value.empty()) {
        std::memcpy(pValue, value.data(), value.size());
    }
    *pulValueLen = static_cast<CK_ULONG>(value.size());
    return CKR_OK;
}

CK_RV AttributeStore::setAttribute(CK_ATTRIBUTE_PTR pAttr) {
    if (pAttr == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }

    // Check if the attribute is read-only
    if (isReadOnly(pAttr->type)) {
        return CKR_ATTRIBUTE_READ_ONLY;
    }

    // Validate the attribute value
    CK_RV rv = validateAttribute(pAttr->type, pAttr->pValue, pAttr->ulValueLen);
    if (rv != CKR_OK) {
        return rv;
    }

    const u8* src = static_cast<const u8*>(pAttr->pValue);

    // Now set the attribute
    switch (pAttr->type) {
        case CKA_CLASS:
        case CKA_TOKEN:
        case CKA_PRIVATE:
            // Class/token/private are immutable; cannot be changed after creation
            return CKR_ATTRIBUTE_READ_ONLY;
        case CKA_ID:
            if (pAttr->ulValueLen > 0) {
                object_.setId({src, pAttr->ulValueLen});
            } else {
                object_.setId({});
            }
            break;
        case CKA_SENSITIVE: {
            if (pAttr->ulValueLen != sizeof(CK_BBOOL)) {
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            CK_BBOOL bValue = *static_cast<CK_BBOOL*>(pAttr->pValue);
            // Once set to true, cannot be set back to false
            if (object_.isSensitive() && !bValue) {
                return CKR_ATTRIBUTE_READ_ONLY;
            }
            object_.sensitive_ = (bValue == CK_TRUE);
            break;
        }
        case CKA_EXTRACTABLE: {
            if (pAttr->ulValueLen != sizeof(CK_BBOOL)) {
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            CK_BBOOL bValue = *static_cast<CK_BBOOL*>(pAttr->pValue);
            // Once set to false, cannot be set back to true
            if (!object_.isExtractable() && bValue) {
                return CKR_ATTRIBUTE_READ_ONLY;
            }
            object_.extractable_ = (bValue == CK_TRUE);
            break;
        }
        default:
            // Generic attribute: persists on the object.
            object_.setAttribute(pAttr->type, src, pAttr->ulValueLen);
            break;
    }

    return CKR_OK;
}

void AttributeStore::initializeDefaultAttributes() {
    // Set default values for common attributes
    // Note: The constructor of HsmObject already sets sensitive_ and extractable_
    // We can set defaults for other attributes here if needed.

    // For now, we rely on the constructor and setAttribute to set values.
    // This method is a placeholder for future expansion.
}

bool AttributeStore::isReadOnly(CK_ATTRIBUTE_TYPE type) const {
    // Certain attributes are read-only after object creation
    switch (type) {
        case CKA_CLASS:
        case CKA_TOKEN:
        case CKA_PRIVATE:
            // These are set at object creation and cannot be changed
            return true;
        case CKA_SENSITIVE:
            // Once sensitive is set to true, it cannot be set to false
            return object_.isSensitive();
        case CKA_EXTRACTABLE:
            // Once extractable is set to false, it cannot be set to true
            return !object_.isExtractable();
        default:
            return false;
    }
}

CK_RV AttributeStore::validateAttribute(CK_ATTRIBUTE_TYPE type, CK_VOID_PTR pValue, CK_ULONG ulValueLen) const {
    if (pValue == nullptr && ulValueLen > 0) {
        return CKR_ARGUMENTS_BAD;
    }

    switch (type) {
        case CKA_CLASS:
            if (ulValueLen != sizeof(CK_ULONG)) {
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            // Validate that the class is one of the valid values
            {
                CK_ULONG classValue = *static_cast<CK_ULONG*>(pValue);
                switch (classValue) {
                    case CKO_DATA:
                    case CKO_CERTIFICATE:
                    case CKO_PUBLIC_KEY:
                    case CKO_PRIVATE_KEY:
                    case CKO_SECRET_KEY:
                    case CKO_HW_FEATURE:
                    case CKO_DOMAIN_PARAMETERS:
                    case CKO_OTHER:
                        break;
                    default:
                        return CKR_ATTRIBUTE_VALUE_INVALID;
                }
            }
            break;
        case CKA_TOKEN:
        case CKA_PRIVATE:
        case CKA_SENSITIVE:
        case CKA_EXTRACTABLE:
            if (ulValueLen != sizeof(CK_BBOOL)) {
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            {
                CK_BBOOL bValue = *static_cast<CK_BBOOL*>(pValue);
                if (bValue != CK_FALSE && bValue != CK_TRUE) {
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
            }
            break;
        default:
            // All other attributes are validated by their consumers.
            break;
    }

    return CKR_OK;
}

} // namespace vhsm::keystore