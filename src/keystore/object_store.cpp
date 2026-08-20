#include "object_store.h"

namespace vhsm::keystore::internal {

v_ObjectStore_M1::v_ObjectStore_M1() : v_next_index_(0) {}

v_ObjectStore_M1::~v_ObjectStore_M1() {}

uint32_t v_ObjectStore_M1::v_extract_index(CK_OBJECT_HANDLE handle) {
  return static_cast<uint32_t>((handle >> 32) & 0xFFFFFFFF);
}

uint32_t v_ObjectStore_M1::v_extract_version(CK_OBJECT_HANDLE handle) {
  return static_cast<uint32_t>(handle & 0xFFFFFFFF);
}

CK_OBJECT_HANDLE v_ObjectStore_M1::v_compose_handle(uint32_t index,
                                                    uint32_t version) {
  return (static_cast<CK_OBJECT_HANDLE>(index) << 32) | version;
}

std::shared_ptr<HsmObject>
v_ObjectStore_M1::v_get_object(CK_OBJECT_HANDLE handle) {
  std::lock_guard<std::mutex> lock(v_mutex_);

  uint32_t index = v_extract_index(handle);
  uint32_t version = v_extract_version(handle);

  if (index >= v_table_.size() || v_table_[index].v_is_free) {
    return nullptr;
  }

  // Version mismatch means the handle was invalidated (reuse attack guard).
  if (v_table_[index].v_version.load() != version) {
    return nullptr;
  }

  // Return a shared_ptr copy: the caller keeps the object alive even if another
  // thread destroys the handle (which only drops the store's own reference).
  return v_table_[index].v_object;
}

std::shared_ptr<const HsmObject>
v_ObjectStore_M1::v_get_object(CK_OBJECT_HANDLE handle) const {
  std::lock_guard<std::mutex> lock(v_mutex_);

  uint32_t index = v_extract_index(handle);
  uint32_t version = v_extract_version(handle);

  if (index >= v_table_.size() || v_table_[index].v_is_free) {
    return nullptr;
  }

  if (v_table_[index].v_version.load() != version) {
    return nullptr;
  }

  return std::shared_ptr<const HsmObject>(v_table_[index].v_object);
}

bool v_ObjectStore_M1::v_destroy_object(CK_OBJECT_HANDLE handle) {
  std::lock_guard<std::mutex> lock(v_mutex_);

  uint32_t index = v_extract_index(handle);
  uint32_t version = v_extract_version(handle);

  if (index >= v_table_.size() || v_table_[index].v_is_free) {
    return false;
  }

  if (v_table_[index].v_version.load() != version) {
    return false;
  }

  // Drop the store's own strong reference. Any holder of a shared_ptr returned
  // earlier keeps the object alive until it releases; the handle is now
  // invalid.
  v_table_[index].v_object.reset();
  v_table_[index].v_is_free = true;
  return true;
}

size_t v_ObjectStore_M1::v_get_object_count() const {
  std::lock_guard<std::mutex> lock(v_mutex_);
  size_t count = 0;
  for (const auto &entry : v_table_) {
    if (!entry.v_is_free && entry.v_object) {
      ++count;
    }
  }
  return count;
}

bool v_ObjectStore_M1::v_is_valid_handle(CK_OBJECT_HANDLE handle) const {
  std::lock_guard<std::mutex> lock(v_mutex_);
  uint32_t index = v_extract_index(handle);
  uint32_t version = v_extract_version(handle);

  if (index >= v_table_.size() || v_table_[index].v_is_free) {
    return false;
  }
  return v_table_[index].v_version.load() == version;
}

} // namespace vhsm::keystore::internal
