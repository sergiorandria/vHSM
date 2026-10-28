#include "attribute_store.h"

#include <cstring>

namespace vhsm::keystore::internal {

namespace {

// Vendor attributes holding DER-encoded private key material. These values
// must stay in sync with src/pkcs11/pkcs11_internal.h; they are duplicated
// here because the keystore layer must not depend on the PKCS#11 facade.
constexpr CK_ATTRIBUTE_TYPE kCkaVhsmRsaPriv = 0x81000001UL;
constexpr CK_ATTRIBUTE_TYPE kCkaVhsmEcPriv = 0x81000003UL;

} // namespace

v_AttributeStore_M1::v_AttributeStore_M1(HsmObject &object)
    : v_object_(object) {}

CK_RV v_AttributeStore_M1::v_get_attribute(CK_ATTRIBUTE_TYPE type,
                                           CK_VOID_PTR pValue,
                                           CK_ULONG_PTR pulValueLen) {
  if (pulValueLen == nullptr) {
    return CKR_ARGUMENTS_BAD;
  }

  std::vector<u8> value;
  bool known = false;

  switch (type) {
  case CKA_CLASS: {
    CK_ULONG classValue = 0;
    switch (v_object_.getType()) {
    case ObjectType::DATA:
      classValue = CKO_DATA;
      break;
    case ObjectType::CERTIFICATE:
      classValue = CKO_CERTIFICATE;
      break;
    case ObjectType::PUBLIC_KEY:
      classValue = CKO_PUBLIC_KEY;
      break;
    case ObjectType::PRIVATE_KEY:
      classValue = CKO_PRIVATE_KEY;
      break;
    case ObjectType::SECRET_KEY:
      classValue = CKO_SECRET_KEY;
      break;
    case ObjectType::HARDWARE_FEATURE:
      classValue = CKO_HW_FEATURE;
      break;
    case ObjectType::DOMAIN_PARAMETERS:
      classValue = CKO_DOMAIN_PARAMETERS;
      break;
    case ObjectType::OTHER:
      classValue = CKO_OTHER;
      break;
    }
    value.resize(sizeof(CK_ULONG));
    std::memcpy(value.data(), &classValue, sizeof(CK_ULONG));
    known = true;
    break;
  }
  case CKA_TOKEN: {
    CK_BBOOL v = v_object_.isToken() ? CK_TRUE : CK_FALSE;
    value.resize(sizeof(CK_BBOOL));
    std::memcpy(value.data(), &v, sizeof(CK_BBOOL));
    known = true;
    break;
  }
  case CKA_PRIVATE: {
    CK_BBOOL v = v_object_.isPrivate() ? CK_TRUE : CK_FALSE;
    value.resize(sizeof(CK_BBOOL));
    std::memcpy(value.data(), &v, sizeof(CK_BBOOL));
    known = true;
    break;
  }
  case CKA_SENSITIVE: {
    CK_BBOOL v = v_object_.isSensitive() ? CK_TRUE : CK_FALSE;
    value.resize(sizeof(CK_BBOOL));
    std::memcpy(value.data(), &v, sizeof(CK_BBOOL));
    known = true;
    break;
  }
  case CKA_EXTRACTABLE: {
    CK_BBOOL v = v_object_.isExtractable() ? CK_TRUE : CK_FALSE;
    value.resize(sizeof(CK_BBOOL));
    std::memcpy(value.data(), &v, sizeof(CK_BBOOL));
    known = true;
    break;
  }
  case CKA_ID: {
    auto idSpan = v_object_.getId();
    value.assign(idSpan.begin(), idSpan.end());
    known = true;
    break;
  }
  case CKA_VALUE:
  case kCkaVhsmRsaPriv:
  case kCkaVhsmEcPriv:
    // Key material is never readable when the object is sensitive or marked
    // non-extractable. This covers CKA_VALUE as well as the vendor DER blobs
    // used by the PKCS#11 layer to reconstruct private keys.
    if (v_object_.isSensitive() || !v_object_.isExtractable()) {
      *pulValueLen = CK_UNAVAILABLE_INFORMATION;
      return CKR_ATTRIBUTE_SENSITIVE;
    }
    [[fallthrough]];
  default: {
    const std::vector<u8> *stored = v_object_.findAttribute(type);
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

CK_RV v_AttributeStore_M1::v_set_attribute(CK_ATTRIBUTE_PTR pAttr) {
  if (pAttr == nullptr) {
    return CKR_ARGUMENTS_BAD;
  }

  if (v_is_read_only(pAttr->type)) {
    return CKR_ATTRIBUTE_READ_ONLY;
  }

  CK_RV rv =
      v_validate_attribute(pAttr->type, pAttr->pValue, pAttr->ulValueLen);
  if (rv != CKR_OK) {
    return rv;
  }

  const u8 *src = static_cast<const u8 *>(pAttr->pValue);

  switch (pAttr->type) {
  case CKA_CLASS:
  case CKA_TOKEN:
  case CKA_PRIVATE:
    return CKR_ATTRIBUTE_READ_ONLY;
  case CKA_ID:
    if (pAttr->ulValueLen > 0) {
      v_object_.setId({src, pAttr->ulValueLen});
    } else {
      v_object_.setId({});
    }
    break;
  case CKA_SENSITIVE: {
    if (pAttr->ulValueLen != sizeof(CK_BBOOL)) {
      return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    CK_BBOOL bValue = *static_cast<CK_BBOOL *>(pAttr->pValue);
    if (v_object_.isSensitive() && !bValue) {
      return CKR_ATTRIBUTE_READ_ONLY;
    }
    v_object_.sensitive_ = (bValue == CK_TRUE);
    break;
  }
  case CKA_EXTRACTABLE: {
    if (pAttr->ulValueLen != sizeof(CK_BBOOL)) {
      return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    CK_BBOOL bValue = *static_cast<CK_BBOOL *>(pAttr->pValue);
    if (!v_object_.isExtractable() && bValue) {
      return CKR_ATTRIBUTE_READ_ONLY;
    }
    v_object_.extractable_ = (bValue == CK_TRUE);
    break;
  }
  default:
    v_object_.setAttribute(pAttr->type, src, pAttr->ulValueLen);
    break;
  }

  return CKR_OK;
}

void v_AttributeStore_M1::v_initialize_default_attributes() {
  // Defaults are established by HsmObject construction + v_set_attribute.
}

bool v_AttributeStore_M1::v_is_read_only(CK_ATTRIBUTE_TYPE type) const {
  switch (type) {
  case CKA_CLASS:
  case CKA_TOKEN:
  case CKA_PRIVATE:
    return true;
  case CKA_SENSITIVE:
    return v_object_.isSensitive();
  case CKA_EXTRACTABLE:
    return !v_object_.isExtractable();
  case kCkaVhsmRsaPriv:
  case kCkaVhsmEcPriv:
    // Private key material is installed by the crypto layer and must never be
    // replaced through C_SetAttributeValue.
    return true;
  case CKA_VALUE:
    // CKA_VALUE is writable for data/certificate objects and non-sensitive
    // secret keys, but private keys and sensitive objects must not have their
    // secret material swapped after creation.
    return v_object_.isSensitive() ||
           v_object_.getType() == ObjectType::PRIVATE_KEY;
  default:
    return false;
  }
}

CK_RV v_AttributeStore_M1::v_validate_attribute(CK_ATTRIBUTE_TYPE type,
                                                CK_VOID_PTR pValue,
                                                CK_ULONG ulValueLen) const {
  if (pValue == nullptr && ulValueLen > 0) {
    return CKR_ARGUMENTS_BAD;
  }

  switch (type) {
  case CKA_CLASS:
    if (ulValueLen != sizeof(CK_ULONG)) {
      return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    {
      CK_ULONG classValue = *static_cast<CK_ULONG *>(pValue);
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
      CK_BBOOL bValue = *static_cast<CK_BBOOL *>(pValue);
      if (bValue != CK_FALSE && bValue != CK_TRUE) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }
    }
    break;
  default:
    break;
  }

  return CKR_OK;
}

} // namespace vhsm::keystore::internal
