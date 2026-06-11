#include "attribute_store.h"

#include <cstring>

namespace vhsm::keystore {

AttributeStore::AttributeStore(HsmObject& object) : object_(object) {}

CK_RV AttributeStore::getAttribute(CK_ATTRIBUTE_TYPE type, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen) {
    // First, determine the size needed for the attribute
    CK_ULONG ulSize = 0;
    //bool bResult = false;

    switch (type) {
        case CKA_CLASS:
            ulSize = sizeof(CK_ULONG);
            //bResult = true;
            break;
        case CKA_TOKEN:
            ulSize = sizeof(CK_BBOOL);
            //bResult = true;
            break;
        case CKA_PRIVATE:
            ulSize = sizeof(CK_BBOOL);
            //bResult = true;
            break;
        case CKA_LABEL: {
            auto it = extraAttrs_.find(CKA_LABEL);
            ulSize = (it != extraAttrs_.end())
                    ? static_cast<CK_ULONG>(it->second.size())
                    : 0;
            break;
        }
        case CKA_ID:
            // ID is stored in the object's id_ (SecureBuffer)
            ulSize = object_.getId().size();
            //bResult = true;
            break;
        case CKA_SENSITIVE:
            ulSize = sizeof(CK_BBOOL);
            //bResult = true;
            break;
        case CKA_EXTRACTABLE:
            ulSize = sizeof(CK_BBOOL);
            //bResult = true;
            break;
        case CKA_VALUE: {
            auto it = extraAttrs_.find(CKA_VALUE);
            ulSize = (it != extraAttrs_.end())
                    ? static_cast<CK_ULONG>(it->second.size())
                    : 0;
            break;
        }
        default:
            return CKR_ATTRIBUTE_TYPE_INVALID;
    }

    if (pulValueLen == nullptr) {
        return CKR_ARGUMENTS_BAD;
    }

    if (pValue == nullptr) {
        // Caller just wants the size
        *pulValueLen = ulSize;
        return CKR_OK;
    }

    if (*pulValueLen < ulSize) {
        *pulValueLen = ulSize;
        return CKR_BUFFER_TOO_SMALL;
    }

    // Now copy the value
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
            ::memcpy(pValue, &classValue, ulSize);
            break;
        }
        case CKA_TOKEN: {
            CK_BBOOL tokenValue = CK_TRUE; // Assume token object
            ::memcpy(pValue, &tokenValue, ulSize);
            break;
        }
        case CKA_PRIVATE: {
            CK_BBOOL privateValue = CK_FALSE; // Assume not private by default
            ::memcpy(pValue, &privateValue, ulSize);
            break;
        }
        case CKA_LABEL: {
            auto it = extraAttrs_.find(CKA_LABEL);
            if (it != extraAttrs_.end() && !it->second.empty()) {
                ::memcpy(pValue, it->second.data(), it->second.size());
                ulSize = static_cast<CK_ULONG>(it->second.size());
            } else {
                ulSize = 0;
            }
            break;
        }
        case CKA_ID: {
            auto idSpan = object_.getId();
            if (idSpan.size() > 0) {
                ::memcpy(pValue, idSpan.data(), idSpan.size());
            } else {
                ::memset(pValue, 0, ulSize);
            }
            break;
        }
        case CKA_SENSITIVE: {
            CK_BBOOL sensitiveValue = object_.isSensitive() ? CK_TRUE : CK_FALSE;
            ::memcpy(pValue, &sensitiveValue, ulSize);
            break;
        }
        case CKA_EXTRACTABLE: {
            CK_BBOOL extractableValue = object_.isExtractable() ? CK_TRUE : CK_FALSE;
            ::memcpy(pValue, &extractableValue, ulSize);
            break;
        }
        case CKA_VALUE: {
            auto it = extraAttrs_.find(CKA_VALUE);
            if (it != extraAttrs_.end() && !it->second.empty()) {
                ::memcpy(pValue, it->second.data(), it->second.size());
                ulSize = static_cast<CK_ULONG>(it->second.size());
            } else {
                ulSize = 0;
            }
            break;
        }
        default:
            return CKR_ATTRIBUTE_TYPE_INVALID;
    }

    *pulValueLen = ulSize;
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

    // Now set the attribute
    switch (pAttr->type) {
        case CKA_CLASS: {
            // Class is immutable; cannot be changed after creation
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        case CKA_TOKEN: {
            // Token is immutable; cannot be changed after creation
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        case CKA_PRIVATE: {
            // Private is immutable; cannot be changed after creation
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        case CKA_LABEL: {
            // Store label in extraAttrs_
            if (pAttr->pValue != nullptr && pAttr->ulValueLen > 0) {
                const u8* src = static_cast<const u8*>(pAttr->pValue);
                extraAttrs_[CKA_LABEL].assign(src, src + pAttr->ulValueLen);
            } else {
                extraAttrs_[CKA_LABEL].clear();
            }
            break;
        }
        case CKA_ID: {
            // Set the object's ID
            if (pAttr->ulValueLen > 0) {
                object_.setId({static_cast<const u8*>(pAttr->pValue), pAttr->ulValueLen});
            } else {
                object_.setId({});
            }
            break;
        }
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
        case CKA_VALUE: {
            const u8* src = static_cast<const u8*>(pAttr->pValue);
            extraAttrs_[pAttr->type].assign(src, src + pAttr->ulValueLen);
            break;
        }
        default:
            return CKR_ATTRIBUTE_TYPE_INVALID;
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
        case CKA_LABEL:
            // Label can be any length, including zero
            break;
        case CKA_ID:
            // ID can be any length, including zero
            break;
        case CKA_VALUE:
            // Value validation is done elsewhere; here we just check length is reasonable
            // In a real implementation, we would validate based on key type.
            break;
        default:
            return CKR_ATTRIBUTE_TYPE_INVALID;
    }

    return CKR_OK;
}

} // namespace vhsm::keystore