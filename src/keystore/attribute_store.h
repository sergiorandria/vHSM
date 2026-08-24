#ifndef VHSM_KEYSTORE_ATTRIBUTE_STORE_H
#define VHSM_KEYSTORE_ATTRIBUTE_STORE_H

#include "../core/secure_buffer.h"
#include "pkcs11/pkcs11_types.h"  // resolved via -I src
#include "../core/types.h"
#include "hsm_object.h"

#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace vhsm::keystore::internal {

// CKA_/CKO_/CKK_* single source: src/pkcs11/pkcs11_types.h (constexpr, global ns).
// Included transitively via hsm_object.h -> core/types.h -> pkcs11_types.h.

/**
 * v_AttributeStore_M1 manages PKCS#11 attributes for HSM objects.
 * Handles get/set operations with enforcement of special attributes.
 * See attribute_store.cpp for the full contract.
 *
 * WHY attribute store separate from object: Attributes are metadata (labels,
 * IDs, key sizes, etc.). HSM objects already hold id_ and attrs_. This class
 * interprets PKCS#11 semantics (which attributes are read-only, how to
 * serialize/deserialize). It's a bridge between the C API (CK_ATTRIBUTE) and
 * C++ objects.
 *
 * WHY takes HsmObject& reference (not owned): The store doesn't own the object.
 * It's constructed per-session to read/write attributes on an object that
 * exists elsewhere (owned by the Token/ObjectStore).
 */
class v_AttributeStore_M1 {
public:
  /**
   * @brief Constructor binds this store to an object for attribute operations.
   * @param object Reference to the HsmObject to manage attributes for.
   *
   * WHY take reference: The object already exists (owned elsewhere). We're just
   * reading/writing its attribute storage during a session. Taking a reference
   * makes this explicit (we don't own the object).
   */
  explicit v_AttributeStore_M1(HsmObject &object);

  /**
   * @brief Retrieve an attribute value from the object.
   * @param type CKA_* attribute type identifier.
   * @param pValue [out] Buffer to write the attribute value.
   * @param pulValueLen [in/out] Buffer size; updated with actual size.
   * @return CKR_OK if successful, CKR_* error codes otherwise.
   *
   * WHY CK_RV return: Matches PKCS#11 C API convention. Callers expect
   * error codes like CKR_ATTRIBUTE_TYPE_INVALID, CKR_BUFFER_TOO_SMALL.
   */
  CK_RV v_get_attribute(CK_ATTRIBUTE_TYPE type, CK_VOID_PTR pValue,
                        CK_ULONG_PTR pulValueLen);

  /**
   * @brief Set an attribute value on the object.
   * @param pAttr Pointer to CK_ATTRIBUTE struct with type and value.
   * @return CKR_OK or error code.
   *
   * WHY take CK_ATTRIBUTE_PTR: This is the C API form. v_AttributeStore_M1
   * is a bridge; using the PKCS#11 struct directly makes it clear.
   */
  CK_RV v_set_attribute(CK_ATTRIBUTE_PTR pAttr);

  /**
   * @brief Initialize default attributes for a newly-created object.
   * Called by the Token after creating an object to set mandatory attributes.
   */
  void v_initialize_default_attributes();

private:
  // WHY reference to the object: This attribute store is transient
  // (per-session). The object lives in the ObjectStore (owned by Token). We
  // just read/write its attributes, so a reference is enough (no ownership).
  HsmObject &v_object_;

  /**
   * @brief Check if an attribute is read-only (can't be modified after
   * creation).
   * @param type CKA_* attribute type.
   * @return true if the attribute is read-only per PKCS#11.
   *
   * WHY separate method: Read-only enforcement is centralized here. When a
   * caller tries to set a read-only attribute, we return
   * CKR_ATTRIBUTE_READ_ONLY. Examples: CKA_CLASS (object type can't change),
   * CKA_KEY_SIZE (key size is immutable).
   */
  bool v_is_read_only(CK_ATTRIBUTE_TYPE type) const;

  /**
   * @brief Validate an attribute value before storing it.
   * @param type CKA_* type.
   * @param pValue Pointer to the value.
   * @param ulValueLen Length of the value.
   * @return CKR_OK or error code if validation fails.
   *
   * WHY centralized validation: Different attributes have different rules
   * (e.g., CKA_LABEL must be a string, CKA_SENSITIVE must be a boolean).
   * Validation ensures only sensible values are stored. Prevents type
   * mismatches and injection attacks.
   */
  CK_RV v_validate_attribute(CK_ATTRIBUTE_TYPE type, CK_VOID_PTR pValue,
                             CK_ULONG ulValueLen) const;
};

} // namespace vhsm::keystore::internal

#endif // VHSM_KEYSTORE_ATTRIBUTE_STORE_H
