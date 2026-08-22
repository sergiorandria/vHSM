#ifndef VHSM_KEYSTORE_HSM_OBJECT_H
#define VHSM_KEYSTORE_HSM_OBJECT_H

#include "../core/secure_buffer.h"
#include "../core/types.h"

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace vhsm::keystore {

namespace internal {
class v_AttributeStore_M1;
} // namespace internal

enum class ObjectType : u8 {
  DATA = 0,
  CERTIFICATE = 1,
  PUBLIC_KEY = 2,
  PRIVATE_KEY = 3,
  SECRET_KEY = 4,
  HARDWARE_FEATURE = 5,
  DOMAIN_PARAMETERS = 6,
  OTHER = 7
};

// WHY: Abstract base class for all keystore objects. We need a unified
// interface because PKCS#11 requires handling diverse object types (keys,
// certs, data) with a single handle-based API. By centralizing type metadata,
// copyability constraints, and attribute storage here, derived classes
// (PrivateKey, Certificate, etc.) inherit consistent semantics without
// reimplementing the same patterns.
//
// WHY non-copyable for sensitive objects: Sensitive key material (private keys,
// secrets) must never be accidentally duplicated via copy constructors—doubling
// the attack surface and memory footprint. The copy constructor explicitly
// checks sensitive_ and throws. Non-sensitive objects (certificates, public
// keys) can be copied for transport across module boundaries.
//
// WHY moves are noexcept: Container operations (e.g., std::vector::push_back)
// require move semantics to be exception-safe. If move threw, the vector would
// be left in an invalid state. noexcept move guarantees atomicity.
//
// WHY SecureBuffer for id_: Even metadata like key IDs can leak information in
// cache or memory dumps. SecureBuffer zeroes memory before deallocation,
// protecting against forensic recovery.
class HsmObject {
public:
  HsmObject(ObjectType type, bool sensitive = false, bool extractable = true,
            bool token = false, bool priv = false);

  virtual ~HsmObject() noexcept;

  // Non-copyable if sensitive; derived classes enforce at construction time.
  HsmObject(const HsmObject &);
  HsmObject &operator=(const HsmObject &);

  // Move, noexcept for container compatibility.
  HsmObject(HsmObject &&) noexcept;
  HsmObject &operator=(HsmObject &&) noexcept;

  // WHY separate getters for each boolean flag: PKCS#11 spec requires
  // individual boolean queries (C_GetObjectAttribute with CKA_SENSITIVE,
  // CKA_EXTRACTABLE, etc.) by callers. Exporting a struct would force callers
  // to request all flags or rebuild from a bitmask. Individual getters align
  // with the standard API.
  ObjectType getType() const noexcept;
  bool isSensitive() const noexcept;
  bool isExtractable() const noexcept;
  bool isToken() const noexcept;
  bool isPrivate() const noexcept;

  // WHY generic attribute storage on the object itself (not external store):
  // PKCS#11 applications set arbitrary CKA_* attributes at runtime (labels,
  // IDs, issuer names). These must persist across token lifecycle and survive
  // Token::Token destruction + recreation. Storing attrs_ on the object ensures
  // they travel with the object in serialization. v_AttributeStore_M1 is
  // declared friend to enforce read-only access for most code (only factory
  // sets attrs).
  //
  // WHY findAttribute returns const pointer (not optional/variant): Pointer
  // allows zero-copy access to the vector. null = not found. Avoids copies or
  // allocation for the common case (attribute not present).
  //
  // WHY setId(span) not setId(vector): Span avoids temporary allocations when
  // the caller already has the ID data in a buffer. Reduces heap pressure in
  // object creation hot paths.
  [[nodiscard]] const std::vector<u8> *
  findAttribute(CK_ATTRIBUTE_TYPE type) const noexcept;
  void setAttribute(CK_ATTRIBUTE_TYPE type, const u8 *data, std::size_t len);

  // WHY returns span not vector: The caller typically loops over the ID for
  // validation or logging. Returning a span avoids a copy and lets the caller
  // decide whether to copy or reference. If idSet_ is false, span is empty
  // (not optional) for simpler error handling.
  //
  // WHY setId(span) overwrites, not appends: Key IDs are immutable once set
  // (PKCS#11 constraint). Allowing append could accidentally create wrong IDs.
  // Full replacement is the only sensible operation.
  std::span<const u8> getId() const noexcept;
  void setId(std::span<const u8> id); // span avoids copying into a temp vector

  virtual std::vector<u8> getPublicKeyInfo() const { return {}; }
  virtual size_t getKeySize() const noexcept { return 0; }

protected:
  // WHY separate wipe() method (not just in destructor): Derived classes must
  // zero their own key material *before* base destructor runs (C++ destruction
  // order is bottom-up, so base wipe() runs last). By calling this virtual
  // wipe(), we ensure each level zeros its data in the correct order,
  // preventing key fragments from surviving on the stack or registers.
  virtual void wipe() noexcept; // override in derived to zero key material

  ObjectType type_;
  bool sensitive_;
  bool extractable_;
  bool token_;
  bool private_;
  SecureBuffer id_;
  bool idSet_;

  // WHY unordered_map<CKA_TYPE, vector> for attrs_: Applications can set
  // hundreds of unique CKA_* attribute types. A map with lazy allocation
  // avoids preallocating space for all possible attributes. unordered_map
  // is O(1) average for get/set. vector<u8> is flexible for variable-length
  // values (booleans, strings, DER-encoded structures, etc.).
  std::unordered_map<CK_ATTRIBUTE_TYPE, std::vector<u8>> attrs_;

  friend class internal::v_AttributeStore_M1;
};
} // namespace vhsm::keystore

#endif // VHSM_KEYSTORE_HSM_OBJECT_H