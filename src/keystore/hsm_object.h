#ifndef VHSM_KEYSTORE_HSM_OBJECT_H
#define VHSM_KEYSTORE_HSM_OBJECT_H

#include "../core/types.h"
#include "../core/secure_buffer.h"

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <span>

namespace vhsm::keystore {
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

// Abstract class, 
// primitive types of the keystore
class HsmObject {
public:
    HsmObject(ObjectType type, bool sensitive = false, bool extractable = true);

    virtual ~HsmObject() noexcept;

    // Non-copyable if sensitive; derived classes enforce at construction time.
    HsmObject(const HsmObject&);
    HsmObject& operator=(const HsmObject&);

    // Move, noexcept for container compatibility.
    HsmObject(HsmObject&&) noexcept;
    HsmObject& operator=(HsmObject&&) noexcept;

    ObjectType getType()      const noexcept;
    bool       isSensitive()  const noexcept;
    bool       isExtractable() const noexcept;

    // Returns a memory view, caller must not outlive this object.
    std::span<const u8> getId() const noexcept;
    void setId(std::span<const u8> id);   // span avoids copying into a temp vector

    virtual std::vector<u8> getPublicKeyInfo() const { return {}; }
    virtual size_t          getKeySize()       const noexcept { return 0; }
    //virtual void            setSensitive(bool sensitive) noexcept { sensitive_ = sensitive; }
    //virtual void            setExtractable(bool extractable) noexcept { extractable_ = extractable; }

protected:
    virtual void wipe() noexcept; // override in derived to zero key material

    ObjectType   type_;
    bool         sensitive_;
    bool         extractable_;
    SecureBuffer id_;

    friend class AttributeStore;
};
} // namespace vhsm::keystore

#endif // VHSM_KEYSTORE_HSM_OBJECT_H