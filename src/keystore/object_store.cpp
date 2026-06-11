#include "object_store.h"

namespace vhsm::keystore {

ObjectStore::ObjectStore() : nextIndex_(0) {
    // Pre-allocate some space to avoid frequent reallocations
    table_.reserve(1024);
}

ObjectStore::~ObjectStore() {
    // All objects will be automatically destroyed by unique_ptr
}

uint32_t ObjectStore::extractIndex(CK_OBJECT_HANDLE handle) {
    // Lower 24 bits are the index
    return handle & 0xFFFFFF;
}

uint32_t ObjectStore::extractVersion(CK_OBJECT_HANDLE handle) {
    // Upper 8 bits are the version
    return (handle >> 24) & 0xFF;
}

CK_OBJECT_HANDLE ObjectStore::composeHandle(uint32_t index, uint32_t version) {
    // Combine index (lower 24 bits) and version (upper 8 bits)
    return (static_cast<CK_OBJECT_HANDLE>(version) << 24) | (index & 0xFFFFFF);
}

HsmObject* ObjectStore::getObject(CK_OBJECT_HANDLE handle) {
    if (handle == CK_INVALID_HANDLE) {
        return nullptr;
    }

    uint32_t index = extractIndex(handle);
    uint32_t version = extractVersion(handle);

    // Check bounds
    if (index >= table_.size()) {
        return nullptr;
    }

    // Check if the slot is free or version doesn't match
    if (table_[index].isFree || table_[index].version.load() != version) {
        return nullptr;
    }

    return table_[index].object.get();
}

const HsmObject* ObjectStore::getObject(CK_OBJECT_HANDLE handle) const {
    // Const version delegates to non-const version
    return const_cast<ObjectStore*>(this)->getObject(handle);
}

bool ObjectStore::destroyObject(CK_OBJECT_HANDLE handle) {
    if (handle == CK_INVALID_HANDLE) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    uint32_t index = extractIndex(handle);
    uint32_t version = extractVersion(handle);

    // Check bounds
    if (index >= table_.size()) {
        return false;
    }

    // Check if the slot is free or version doesn't match
    if (table_[index].isFree || table_[index].version.load() != version) {
        return false;
    }

    // Mark as free and destroy the object
    table_[index].isFree = true;
    table_[index].object.reset();  // This will call the object's destructor
    // Note: We don't increment version here to keep it simple, but we could
    // to prevent handle reuse immediately

    return true;
}

size_t ObjectStore::getObjectCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& entry : table_) {
        if (!entry.isFree) {
            ++count;
        }
    }
    return count;
}

bool ObjectStore::isValidHandle(CK_OBJECT_HANDLE handle) const {
    if (handle == CK_INVALID_HANDLE) {
        return false;
    }

    uint32_t index = extractIndex(handle);
    uint32_t version = extractVersion(handle);

    // Check bounds
    if (index >= table_.size()) {
        return false;
    }

    // Check if the slot is free or version doesn't match
    return !table_[index].isFree && (table_[index].version.load() == version);
}

} // namespace vhsm::keystore