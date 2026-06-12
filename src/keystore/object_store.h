#ifndef VHSM_KEYSTORE_OBJECT_STORE_H
#define VHSM_KEYSTORE_OBJECT_STORE_H

#include "../core/types.h"
#include "hsm_object.h"

#include <memory>
#include <vector>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <stdexcept>

namespace vhsm::keystore {

/**
 * ObjectStore manages HSM objects and their handles.
 * Implements handle allocation similar to a GDT (Global Descriptor Table)
 * where each valid object gets a unique CK_OBJECT_HANDLE.
 *
 * The handle is essentially an index into an internal table, with
 * additional bits for version tracking to prevent handle reuse attacks.
 */
class ObjectStore {
public:
    ObjectStore();
    ~ObjectStore();

    // Non-copyable
    ObjectStore(const ObjectStore&) = delete;
    ObjectStore& operator=(const ObjectStore&) = delete;

    /**
     * Create a new HsmObject and allocate a handle for it.
     * @tparam T Type of HsmObject to create (must derive from HsmObject)
     * @tparam Args Constructor argument types
     * @param args Arguments to forward to the object constructor
     * @return Pair of (handle, pointer to object) or (CK_INVALID_HANDLE, nullptr) on failure
     */
    template<typename T, typename... Args>
    std::pair<CK_OBJECT_HANDLE, T*> createObject(Args&&... args);

    /**
     * Get an object by its handle.
     * @param handle The object handle
     * @return Pointer to the object if handle is valid, nullptr otherwise
     */
    [[nodiscard]]
    HsmObject* getObject(CK_OBJECT_HANDLE handle);

    /**
     * Get a const object by its handle.
     * @param handle The object handle
     * @return Const pointer to the object if handle is valid, nullptr otherwise
     */
    [[nodiscard]]
    const HsmObject* getObject(CK_OBJECT_HANDLE handle) const;

    /**
     * Destroy an object and free its handle.
     * @param handle The object handle to destroy
     * @return true if object was found and destroyed, false otherwise
     */
    bool destroyObject(CK_OBJECT_HANDLE handle);

    /**
     * Get the total number of objects currently in the store.
     * @return Number of active objects
     */
    size_t getObjectCount() const;

    /**
     * Check if a handle is valid.
     * @param handle The handle to check
     * @return true if handle is valid, false otherwise
     */
    bool isValidHandle(CK_OBJECT_HANDLE handle) const;

private:
    // Entry in the object store table
    struct ObjectEntry {
        std::unique_ptr<HsmObject> object;
        std::atomic<uint32_t> version;  // For handle validation
        bool isFree;                    // Whether this slot is free

        ObjectEntry() : version(0), isFree(true) {}

        // Delete copy constructor and copy assignment due to atomic member
        ObjectEntry(const ObjectEntry&) = delete;
        ObjectEntry& operator=(const ObjectEntry&) = delete;

        // Allow move operations
        ObjectEntry(ObjectEntry&& other) noexcept
            : object(std::move(other.object)),
                version(other.version.load()),  // Note: This is not atomic access, but OK for move
                isFree(other.isFree) {
            // After moving, mark source as free to prevent double destruction
            other.isFree = true;
        }

        ObjectEntry& operator=(ObjectEntry&& other) noexcept {
            if (this != &other) {
                object = std::move(other.object);
                version.store(other.version.load());
                isFree = other.isFree;
                // After moving, mark source as free to prevent double destruction
                other.isFree = true;
            }
            return *this;
        }
    };

    // Special handle value for invalid handle
    static constexpr CK_OBJECT_HANDLE CK_INVALID_HANDLE = 0;

    // Extract index and version from handle
    static uint32_t extractIndex(CK_OBJECT_HANDLE handle);
    static uint32_t extractVersion(CK_OBJECT_HANDLE handle);
    static CK_OBJECT_HANDLE composeHandle(uint32_t index, uint32_t version);

    std::vector<ObjectEntry> table_;
    mutable std::mutex mutex_;
    std::atomic<uint32_t> nextIndex_;  // Next index to try for allocation
};

// Special handle value for invalid handle
inline constexpr CK_OBJECT_HANDLE CK_INVALID_HANDLE = 0;

} // namespace vhsm::keystore

// Template implementation
namespace vhsm::keystore {

template<typename T, typename... Args>
std::pair<CK_OBJECT_HANDLE, T*> ObjectStore::createObject(Args&&... args) {
    static_assert(std::is_base_of_v<HsmObject, T>, "T must derive from HsmObject");

    std::lock_guard<std::mutex> lock(mutex_);

    // Find a free slot
    for (size_t i = 0; i < table_.size(); ++i) {
        size_t index = (nextIndex_ + i) % table_.size();
        if (table_[index].isFree) {
            // Found a free slot
            table_[index].isFree = false;
            table_[index].version.fetch_add(1);  // Increment version
            uint32_t version = table_[index].version.load();

            // Create the object
            table_[index].object = std::make_unique<T>(std::forward<Args>(args)...);

            // Compose handle
            CK_OBJECT_HANDLE handle = composeHandle(index, version);
            return {handle, static_cast<T*>(table_[index].object.get())};
        }
    }

    // No free slot found, expand the table
    size_t index = table_.size();
    table_.emplace_back();
    table_[index].isFree = false;
    table_[index].version.fetch_add(1);
    uint32_t version = table_[index].version.load();

    // Create the object
    table_[index].object = std::make_unique<T>(std::forward<Args>(args)...);

    // Compose handle
    CK_OBJECT_HANDLE handle = composeHandle(index, version);
    return {handle, static_cast<T*>(table_[index].object.get())};
}
} // namespace vhsm::keystore

#endif // VHSM_KEYSTORE_OBJECT_STORE_H