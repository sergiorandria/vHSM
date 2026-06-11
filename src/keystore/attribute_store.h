#ifndef VHSM_KEYSTORE_ATTRIBUTE_STORE_H
#define VHSM_KEYSTORE_ATTRIBUTE_STORE_H

#include "../core/types.h"
#include "../core/secure_buffer.h"
#include "hsm_object.h"

#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace vhsm::keystore {

// PKCS#11 Attribute Types (subset needed for HSM object management)
constexpr CK_ULONG CKA_CLASS            = 0x00000000;
constexpr CK_ULONG CKA_TOKEN            = 0x00000001;
constexpr CK_ULONG CKA_PRIVATE          = 0x00000002;
constexpr CK_ULONG CKA_LABEL            = 0x00000003;
constexpr CK_ULONG CKA_ID               = 0x000000102;
constexpr CK_ULONG CKA_SENSITIVE        = 0x000000103;
constexpr CK_ULONG CKA_EXTRACTABLE      = 0x000000162;
constexpr CK_ULONG CKA_VALUE            = 0x00000011;

// Object Classes
constexpr CK_ULONG CKO_DATA             = 0x00000000;
constexpr CK_ULONG CKO_CERTIFICATE      = 0x00000001;
constexpr CK_ULONG CKO_PUBLIC_KEY       = 0x00000002;
constexpr CK_ULONG CKO_PRIVATE_KEY      = 0x00000003;
constexpr CK_ULONG CKO_SECRET_KEY       = 0x00000004;
constexpr CK_ULONG CKO_HW_FEATURE       = 0x00000005;
constexpr CK_ULONG CKO_DOMAIN_PARAMETERS= 0x00000006;
constexpr CK_ULONG CKO_OTHER            = 0x00000010;

/**
 * AttributeStore manages PKCS#11 attributes for HSM objects.
 * Handles get/set operations with enforcement of special attributes:
 * - CKA_SENSITIVE: When true, object becomes non-copyable
 * - CKA_EXTRACTABLE: When false, prevents key extraction
 * - Read-only attributes: CKA_TOKEN, CKA_PRIVATE (after initialization)
 */
class AttributeStore {
public:
    explicit AttributeStore(HsmObject& object);

    /**
     * Get an attribute value.
     * @param type  Attribute type (CKA_*)
     * @param pValue Pointer to buffer to receive value (can be null to get size)
     * @param pulValueLen IN/OUT: pointer to length of pValue buffer
     * @return CKR_OK on success, or appropriate error code
     */
    CK_RV getAttribute(CK_ATTRIBUTE_TYPE type, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen);

    /**
     * Set an attribute value.
     * Enforces constraints:
     * - CKA_SENSITIVE: Can only be set to false if currently false (read-only after set to true)
     * - CKA_EXTRACTABLE: Can only be set to false if currently true (read-only after set to false)
     * - Certain attributes are read-only after object initialization (CKA_TOKEN, CKA_PRIVATE)
     * @param pAttr  Pointer to CK_ATTRIBUTE containing type and value
     * @return CKR_OK on success, or appropriate error code
     */
    CK_RV setAttribute(CK_ATTRIBUTE_PTR pAttr);

    /**
     * Initialize default attributes for a new object.
     * Sets CKA_CLASS based on object type, and reasonable defaults for other attributes.
     */
    void initializeDefaultAttributes();

private:
    HsmObject& object_;
    
    // Holds blob attributes that have no dedicated field in HsmObject
    // (CKA_LABEL, CKA_VALUE). Key = CKA_* constant, value = raw bytes.
    // Maybe a hardened data structure is preferred here.
    std::unordered_map<CK_ATTRIBUTE_TYPE, std::vector<u8>> extraAttrs_;


    // Helper to check if an attribute is read-only for this object
    bool isReadOnly(CK_ATTRIBUTE_TYPE type) const;

    // Helper to validate attribute value against constraints
    CK_RV validateAttribute(CK_ATTRIBUTE_TYPE type, CK_VOID_PTR pValue, CK_ULONG ulValueLen) const;
};

} // namespace vhsm::keystore

#endif // VHSM_KEYSTORE_ATTRIBUTE_STORE_H