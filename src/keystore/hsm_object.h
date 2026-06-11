#ifndef VHSM_KEYSTORE_HSM_OBJECT_H
#define VHSM_KEYSTORE_HSM_OBJECT_H

#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace vhsm::keystore {

// Forward declaration
class Attribute;

// Base class for all HSM objects (keys, certificates, data)
class HsmObject {
public:
    enum class ObjectType : uint8_t {
        DATA = 0,
        CERTIFICATE = 1,
        PUBLIC_KEY = 2,
        PRIVATE_KEY = 3,
        SECRET_KEY = 4,
        HARDWARE_FEATURE = 5,
        DOMAIN_PARAMETERS = 6,
        OTHER = 7
    };

    HsmObject(ObjectType type, bool sensitive = false, bool extractable = true);
    virtual ~HsmObject() = default;

    // Getters
    ObjectType getType() const;
    bool isSensitive() const;
    bool isExtractable() const;
    const std::vector<uint8_t>& getId() const;  // CKA_ID
    void setId(const std::vector<uint8_t>& id);

    // Virtual methods for derived classes to implement
    virtual std::vector<uint8_t> getPublicKeyInfo() const { return {}; }
    virtual size_t getKeySize() const { return 0; }

protected:
    ObjectType type_;
    bool sensitive_;      // CKA_SENSITIVE
    bool extractable_;    // CKA_EXTRACTABLE
    std::vector<uint8_t> id_;  // CKA_ID - can be empty
};

} // namespace vhsm::keystore

#endif // VHSM_KEYSTORE_HSM_OBJECT_H