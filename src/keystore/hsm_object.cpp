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
    : type_(type), sensitive_(sensitive), extractable_(extractable),
      token_(token), private_(priv), id_(), idSet_(false), attrs_() {}

HsmObject::~HsmObject() noexcept { wipe(); }

// WHY copy constructor checks sensitive_ and throws: We want PKCS#11 compliance
// (sensitive objects are non-copyable) but also want to catch bugs early.
// Throwing in copy construction (rather than silently failing or using a
// deleted copy ctor) alerts developers that they've attempted an invalid
// operation. Using a runtime check instead of = delete allows non-sensitive
// subclasses to enable copies if needed without reimplementing the entire copy
// constructor.
HsmObject::HsmObject(const HsmObject &other)
    : type_(other.type_), sensitive_(other.sensitive_),
      extractable_(other.extractable_), token_(other.token_),
      private_(other.private_), idSet_(false), attrs_(other.attrs_) {
  VHSM_CHECK_MSG(!sensitive_,
                 "HsmObject: copy of sensitive object is not permitted");

  if (other.idSet_ && other.id_.size() > 0) {
    id_ = SecureBuffer(other.id_.size());
    id_.write(0, other.id_.data(), other.id_.size());
    idSet_ = true;
  }
}

HsmObject &HsmObject::operator=(const HsmObject &other) {
  if (this == &other)
    return *this;

  // WHY check both before assignment: If either object is sensitive, reject the
  // operation. We check before any mutations so that *this is unchanged on
  // error.
  if (sensitive_ || other.sensitive_) {
    throw std::runtime_error(
        "HsmObject: copy-assignment of sensitive object is not permitted");
  }

  // WHY wipe() before overwriting: If *this held previous data (from a prior
  // assignment), zero it to prevent it from lingering in memory after we
  // overwrite the pointers. This is especially important if *this was
  // temporary.
  wipe();

  type_ = other.type_;
  sensitive_ = other.sensitive_;
  extractable_ = other.extractable_;
  token_ = other.token_;
  private_ = other.private_;
  attrs_ = other.attrs_;

  // WHY conditional copy of id_: idSet_ may be false, meaning id_ is not
  // initialized. Only copy if the source has set it.
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

HsmObject::HsmObject(HsmObject &&other) noexcept
    : type_(other.type_), sensitive_(other.sensitive_),
      extractable_(other.extractable_), token_(other.token_),
      private_(other.private_), id_(std::move(other.id_)), idSet_(other.idSet_),
      attrs_(std::move(other.attrs_)) {
  // WHY reset other's state after move: After moving data out, *other is now
  // in a "moved-from" state. We must leave it in a valid state (safe to
  // destroy). Resetting to default values ensures ~other doesn't try to wipe
  // garbage data or call virtual functions on a partially-destructed object.
  other.type_ = ObjectType::OTHER;
  other.sensitive_ = false;
  other.extractable_ = false;
  other.token_ = false;
  other.private_ = false;
  other.idSet_ = false;
}

HsmObject &HsmObject::operator=(HsmObject &&other) noexcept {
  if (this == &other)
    return *this;

  // WHY wipe() before move-assign: Destroy *this's old state to prevent leaks.
  // Example: if *this was a key object, wipe() zeros the old key material.
  wipe();

  type_ = other.type_;
  idSet_ = other.idSet_;
  sensitive_ = other.sensitive_;
  extractable_ = other.extractable_;
  token_ = other.token_;
  private_ = other.private_;
  id_ = std::move(other.id_);
  attrs_ = std::move(other.attrs_);

  // WHY reset other to valid state: Same reason as move constructor.
  // After move, *other must be safe to destroy.
  other.type_ = ObjectType::OTHER;
  other.sensitive_ = false;
  other.extractable_ = false;
  other.token_ = false;
  other.private_ = false;
  other.idSet_ = false;

  return *this;
}

ObjectType HsmObject::getType() const noexcept { return type_; }

bool HsmObject::isSensitive() const noexcept { return sensitive_; }

bool HsmObject::isExtractable() const noexcept { return extractable_; }

bool HsmObject::isToken() const noexcept { return token_; }

bool HsmObject::isPrivate() const noexcept { return private_; }

const std::vector<u8> *
HsmObject::findAttribute(CK_ATTRIBUTE_TYPE type) const noexcept {
  auto it = attrs_.find(type);
  if (it == attrs_.end()) {
    return nullptr;
  }
  return &it->second;
}

void HsmObject::setAttribute(CK_ATTRIBUTE_TYPE type, const u8 *data,
                             std::size_t len) {
  if (len > 0 && data == nullptr) {
    throw std::invalid_argument(
        "HsmObject::setAttribute: null data with non-zero length");
  }
  // WHY clear instead of erase when len==0: Applications often clear attributes
  // by calling setAttribute(type, nullptr, 0). Keeping the map entry but with
  // an empty vector is faster than erasing (avoids reallocation). The entry
  // will be tiny, and future sets to the same attribute reuse it.
  if (len == 0) {
    attrs_[type].clear();
    return;
  }
  // WHY assign not insert_or_assign: insert_or_assign returns a pair with
  // "inserted" flag, which we don't need. assign() is cleaner and updates
  // existing or inserts new.
  attrs_[type].assign(data, data + len);
}

std::span<const u8> HsmObject::getId() const noexcept {
  if (!idSet_)
    return {};
  return {id_.data(), id_.size()};
}

void HsmObject::setId(std::span<const u8> id) {
  // WHY empty span clears: PKCS#11 allows applications to unset attributes.
  // Empty span signals "clear this ID". We reset idSet_ to false and deallocate
  // id_ to reclaim memory and signal that no ID is set.
  if (id.empty()) {
    id_ = SecureBuffer{};
    idSet_ = false;
    return;
  }

  // WHY allocate fresh SecureBuffer each time: Each setId call may use a
  // different-length ID. Allocating new prevents size mismatches and ensures
  // the old buffer (if any) is securely wiped before deallocation.
  id_ = SecureBuffer(id.size());
  idSet_ = true;
  id_.write(0, id.data(), id.size());
}

// WHY wipe() zeros attrs_ by hand with volatile pointers: We can't rely on
// std::fill or memset being optimized away by the compiler. Using volatile
// pointers forces the compiler to generate actual write instructions. This
// prevents the optimizer from eliminating "dead writes" that actually wipe
// sensitive data. We iterate byte-by-byte to ensure every byte is touched.
//
// WHY iterate vector.data() with volatile char*, not use OPENSSL_cleanse:
// OPENSSL_cleanse is great, but we're wiping multiple vectors in a loop.
// Volatile pointer write is portable and works on all platforms without
// linking to OpenSSL (which may not be available everywhere).
void HsmObject::wipe() noexcept {
  id_.wipe();
  for (auto &[type, value] : attrs_) {
    (void)type;
    if (!value.empty()) {
      volatile unsigned char *p = value.data();
      for (std::size_t i = 0; i < value.size(); ++i) {
        p[i] = 0;
      }
    }
  }
  attrs_.clear();
  idSet_ = false;
  sensitive_ = false;
  extractable_ = false;
  token_ = false;
  private_ = false;
}
} // namespace vhsm::keystore