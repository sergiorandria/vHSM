#include "object_store.h"
#include "attribute_store.h"

#include <shared_mutex>

namespace vhsm::keystore::internal {

v_ObjectStore_M1::v_ObjectStore_M1() : v_free_head_(UINT32_MAX) {}

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

std::string v_ObjectStore_M1::v_extract_label(const HsmObject *obj) const {
  if (!obj) return {};
  auto *vec = obj->findAttribute(CKA_LABEL);
  if (!vec || vec->empty()) return {};
  return std::string(vec->begin(), vec->end());
}

std::string v_ObjectStore_M1::v_extract_id(const HsmObject *obj) const {
  if (!obj) return {};
  // Try CKA_ID attribute first, then SecureBuffer id
  auto *vec = obj->findAttribute(CKA_ID);
  if (vec && !vec->empty()) {
    return std::string(vec->begin(), vec->end());
  }
  auto span = obj->getId();
  if (!span.empty()) {
    return std::string(reinterpret_cast<const char*>(span.data()), span.size());
  }
  return {};
}

uint32_t v_ObjectStore_M1::v_extract_class(const HsmObject *obj) const {
  if (!obj) return 0xFFFFFFFF;
  return static_cast<uint32_t>(obj->getType());
}

void v_ObjectStore_M1::v_index_insert(uint32_t index, const HsmObject *obj) {
  if (!obj) return;
  std::string label = v_extract_label(obj);
  if (!label.empty()) {
    v_label_index_.emplace(label, index);
  }
  std::string id = v_extract_id(obj);
  if (!id.empty()) {
    v_id_index_.emplace(id, index);
  }
  uint32_t cls = v_extract_class(obj);
  if (cls != 0xFFFFFFFF) {
    v_class_index_.emplace(cls, index);
  }
}

void v_ObjectStore_M1::v_index_remove(uint32_t index, const HsmObject *obj) {
  if (!obj) return;
  std::string label = v_extract_label(obj);
  if (!label.empty()) {
    auto range = v_label_index_.equal_range(label);
    for (auto it = range.first; it != range.second; ++it) {
      if (it->second == index) {
        v_label_index_.erase(it);
        break;
      }
    }
  }
  std::string id = v_extract_id(obj);
  if (!id.empty()) {
    auto range = v_id_index_.equal_range(id);
    for (auto it = range.first; it != range.second; ++it) {
      if (it->second == index) {
        v_id_index_.erase(it);
        break;
      }
    }
  }
  uint32_t cls = v_extract_class(obj);
  if (cls != 0xFFFFFFFF) {
    auto range = v_class_index_.equal_range(cls);
    for (auto it = range.first; it != range.second; ++it) {
      if (it->second == index) {
        v_class_index_.erase(it);
        break;
      }
    }
  }
}

std::shared_ptr<HsmObject>
v_ObjectStore_M1::v_get_object(CK_OBJECT_HANDLE handle) {
  std::shared_lock<std::shared_mutex> lock(v_mutex_);

  uint32_t index = v_extract_index(handle);
  uint32_t version = v_extract_version(handle);

  if (index >= v_table_.size() || v_table_[index].v_is_free) {
    return nullptr;
  }

  // Version mismatch means the handle was invalidated (reuse attack guard).
  if (v_table_[index].v_version.load(std::memory_order_acquire) != version) {
    return nullptr;
  }

  // Return a shared_ptr copy: the caller keeps the object alive even if another
  // thread destroys the handle (which only drops the store's own reference).
  return v_table_[index].v_object;
}

std::shared_ptr<const HsmObject>
v_ObjectStore_M1::v_get_object(CK_OBJECT_HANDLE handle) const {
  std::shared_lock<std::shared_mutex> lock(v_mutex_);

  uint32_t index = v_extract_index(handle);
  uint32_t version = v_extract_version(handle);

  if (index >= v_table_.size() || v_table_[index].v_is_free) {
    return nullptr;
  }

  if (v_table_[index].v_version.load(std::memory_order_acquire) != version) {
    return nullptr;
  }

  return std::shared_ptr<const HsmObject>(v_table_[index].v_object);
}

bool v_ObjectStore_M1::v_destroy_object(CK_OBJECT_HANDLE handle) {
  std::unique_lock<std::shared_mutex> lock(v_mutex_);

  uint32_t index = v_extract_index(handle);
  uint32_t version = v_extract_version(handle);

  if (index >= v_table_.size() || v_table_[index].v_is_free) {
    return false;
  }

  if (v_table_[index].v_version.load(std::memory_order_acquire) != version) {
    return false;
  }

  // Remove from secondary indices before freeing
  v_index_remove(index, v_table_[index].v_object.get());

  // Drop the store's own strong reference. Any holder of a shared_ptr returned
  // earlier keeps the object alive until it releases; the handle is now
  // invalid.
  v_table_[index].v_object.reset();
  v_table_[index].v_is_free = true;
  v_table_[index].v_next_free = v_free_head_;
  v_free_head_ = index;
  return true;
}

size_t v_ObjectStore_M1::v_get_object_count() const {
  std::shared_lock<std::shared_mutex> lock(v_mutex_);
  size_t count = 0;
  for (const auto &entry : v_table_) {
    if (!entry.v_is_free && entry.v_object) {
      ++count;
    }
  }
  return count;
}

bool v_ObjectStore_M1::v_is_valid_handle(CK_OBJECT_HANDLE handle) const {
  std::shared_lock<std::shared_mutex> lock(v_mutex_);
  uint32_t index = v_extract_index(handle);
  uint32_t version = v_extract_version(handle);

  if (index >= v_table_.size() || v_table_[index].v_is_free) {
    return false;
  }
  return v_table_[index].v_version.load(std::memory_order_acquire) == version;
}

std::pair<CK_OBJECT_HANDLE, std::shared_ptr<HsmObject>>
v_ObjectStore_M1::v_find_by_attributes(
    const std::unordered_map<CK_ATTRIBUTE_TYPE, std::vector<uint8_t>> &templ) const {
  // Fast path for indexed attributes: CKA_CLASS, CKA_LABEL, CKA_ID
  // Choose smallest bucket to iterate.
  std::shared_lock<std::shared_mutex> lock(v_mutex_);

  std::vector<uint32_t> candidates;
  bool has_indexed = false;

  // Check for class
  auto it_class = templ.find(CKA_CLASS);
  if (it_class != templ.end() && it_class->second.size() == sizeof(CK_OBJECT_CLASS)) {
    CK_OBJECT_CLASS cls;
    std::memcpy(&cls, it_class->second.data(), sizeof(cls));
    auto range = v_class_index_.equal_range(static_cast<uint32_t>(cls));
    if (range.first == range.second) {
      return {CK_INVALID_HANDLE, nullptr}; // no match for class
    }
    // Use class bucket as candidates
    for (auto it = range.first; it != range.second; ++it) {
      candidates.push_back(it->second);
    }
    has_indexed = true;
  }

  // Check for label
  auto it_label = templ.find(CKA_LABEL);
  if (it_label != templ.end()) {
    std::string label(it_label->second.begin(), it_label->second.end());
    auto range = v_label_index_.equal_range(label);
    if (range.first == range.second) {
      return {CK_INVALID_HANDLE, nullptr};
    }
    if (!has_indexed) {
      candidates.clear();
      for (auto it = range.first; it != range.second; ++it) candidates.push_back(it->second);
      has_indexed = true;
    } else {
      // Intersect with existing candidates
      std::unordered_map<uint32_t, bool> existing(candidates.size()*2);
      for (auto idx : candidates) existing[idx] = true;
      std::vector<uint32_t> intersect;
      for (auto it = range.first; it != range.second; ++it) {
        if (existing.count(it->second)) intersect.push_back(it->second);
      }
      candidates.swap(intersect);
      if (candidates.empty()) return {CK_INVALID_HANDLE, nullptr};
    }
  }

  // Check for ID
  auto it_id = templ.find(CKA_ID);
  if (it_id != templ.end()) {
    std::string id(it_id->second.begin(), it_id->second.end());
    auto range = v_id_index_.equal_range(id);
    if (range.first == range.second) {
      return {CK_INVALID_HANDLE, nullptr};
    }
    if (!has_indexed) {
      candidates.clear();
      for (auto it = range.first; it != range.second; ++it) candidates.push_back(it->second);
      has_indexed = true;
    } else {
      std::unordered_map<uint32_t, bool> existing(candidates.size()*2);
      for (auto idx : candidates) existing[idx] = true;
      std::vector<uint32_t> intersect;
      for (auto it = range.first; it != range.second; ++it) {
        if (existing.count(it->second)) intersect.push_back(it->second);
      }
      candidates.swap(intersect);
      if (candidates.empty()) return {CK_INVALID_HANDLE, nullptr};
    }
  }

  if (!has_indexed) {
    // No indexed attribute in template, fallback to linear scan
    // Snapshot and release lock, then evaluate outside
    std::vector<std::pair<uint32_t, std::shared_ptr<HsmObject>>> snapshot;
    snapshot.reserve(v_table_.size());
    for (size_t i = 0; i < v_table_.size(); ++i) {
      if (!v_table_[i].v_is_free && v_table_[i].v_object) {
        snapshot.emplace_back(i, v_table_[i].v_object);
      }
    }
    lock.unlock();
    for (auto &[idx, obj] : snapshot) {
      bool match = true;
      for (auto &kv : templ) {
        auto *attr = obj->findAttribute(kv.first);
        if (!attr || *attr != kv.second) { match = false; break; }
      }
      if (match) {
        std::shared_lock<std::shared_mutex> lock2(v_mutex_);
        if (idx >= v_table_.size() || v_table_[idx].v_is_free || !v_table_[idx].v_object) continue;
        if (v_table_[idx].v_object.get() != obj.get()) continue;
        uint32_t version = v_table_[idx].v_version.load(std::memory_order_acquire);
        return {v_compose_handle(idx, version), obj};
      }
    }
    return {CK_INVALID_HANDLE, nullptr};
  }

  // For indexed candidates, verify full template (including non-indexed attrs)
  // Copy candidates to snapshot with shared_ptr to evaluate outside lock
  std::vector<std::pair<uint32_t, std::shared_ptr<HsmObject>>> snapshot;
  snapshot.reserve(candidates.size());
  for (auto idx : candidates) {
    if (idx < v_table_.size() && !v_table_[idx].v_is_free && v_table_[idx].v_object) {
      snapshot.emplace_back(idx, v_table_[idx].v_object);
    }
  }
  lock.unlock();
  for (auto &[idx, obj] : snapshot) {
    bool match = true;
    for (auto &kv : templ) {
      auto *attr = obj->findAttribute(kv.first);
      if (!attr || *attr != kv.second) { match = false; break; }
    }
    if (match) {
      std::shared_lock<std::shared_mutex> lock2(v_mutex_);
      if (idx >= v_table_.size() || v_table_[idx].v_is_free || !v_table_[idx].v_object) continue;
      if (v_table_[idx].v_object.get() != obj.get()) continue;
      uint32_t version = v_table_[idx].v_version.load(std::memory_order_acquire);
      return {v_compose_handle(idx, version), obj};
    }
  }
  return {CK_INVALID_HANDLE, nullptr};
}

std::vector<CK_OBJECT_HANDLE>
v_ObjectStore_M1::v_find_all_by_attributes(
    const std::unordered_map<CK_ATTRIBUTE_TYPE, std::vector<uint8_t>> &templ) const {
  if (templ.empty()) {
    // Find all: return every live handle
    std::shared_lock<std::shared_mutex> lock(v_mutex_);
    std::vector<CK_OBJECT_HANDLE> out;
    out.reserve(v_table_.size());
    for (size_t i = 0; i < v_table_.size(); ++i) {
      if (!v_table_[i].v_is_free && v_table_[i].v_object) {
        uint32_t ver = v_table_[i].v_version.load(std::memory_order_acquire);
        out.push_back(v_compose_handle(i, ver));
      }
    }
    return out;
  }

  // Use indexed path to get candidate indices, then verify full template
  std::shared_lock<std::shared_mutex> lock(v_mutex_);
  std::vector<uint32_t> candidates;
  bool has_indexed = false;

  auto it_class = templ.find(CKA_CLASS);
  if (it_class != templ.end() && it_class->second.size() == sizeof(CK_OBJECT_CLASS)) {
    CK_OBJECT_CLASS cls;
    std::memcpy(&cls, it_class->second.data(), sizeof(cls));
    auto range = v_class_index_.equal_range(static_cast<uint32_t>(cls));
    if (range.first == range.second) return {};
    for (auto it = range.first; it != range.second; ++it) candidates.push_back(it->second);
    has_indexed = true;
  }
  auto it_label = templ.find(CKA_LABEL);
  if (it_label != templ.end()) {
    std::string label(it_label->second.begin(), it_label->second.end());
    auto range = v_label_index_.equal_range(label);
    if (range.first == range.second) return {};
    if (!has_indexed) {
      for (auto it = range.first; it != range.second; ++it) candidates.push_back(it->second);
      has_indexed = true;
    } else {
      std::unordered_map<uint32_t, bool> existing(candidates.size()*2);
      for (auto idx : candidates) existing[idx] = true;
      std::vector<uint32_t> inter;
      for (auto it = range.first; it != range.second; ++it) if (existing.count(it->second)) inter.push_back(it->second);
      candidates.swap(inter);
      if (candidates.empty()) return {};
    }
  }
  auto it_id = templ.find(CKA_ID);
  if (it_id != templ.end()) {
    std::string id(it_id->second.begin(), it_id->second.end());
    auto range = v_id_index_.equal_range(id);
    if (range.first == range.second) return {};
    if (!has_indexed) {
      for (auto it = range.first; it != range.second; ++it) candidates.push_back(it->second);
      has_indexed = true;
    } else {
      std::unordered_map<uint32_t, bool> existing(candidates.size()*2);
      for (auto idx : candidates) existing[idx] = true;
      std::vector<uint32_t> inter;
      for (auto it = range.first; it != range.second; ++it) if (existing.count(it->second)) inter.push_back(it->second);
      candidates.swap(inter);
      if (candidates.empty()) return {};
    }
  }

  std::vector<std::pair<uint32_t, std::shared_ptr<HsmObject>>> snapshot;
  if (has_indexed) {
    snapshot.reserve(candidates.size());
    for (auto idx : candidates) {
      if (idx < v_table_.size() && !v_table_[idx].v_is_free && v_table_[idx].v_object) {
        snapshot.emplace_back(idx, v_table_[idx].v_object);
      }
    }
  } else {
    snapshot.reserve(v_table_.size());
    for (size_t i = 0; i < v_table_.size(); ++i) {
      if (!v_table_[i].v_is_free && v_table_[i].v_object) snapshot.emplace_back(i, v_table_[i].v_object);
    }
  }
  lock.unlock();
  std::vector<CK_OBJECT_HANDLE> out;
  out.reserve(snapshot.size());
  for (auto &[idx, obj] : snapshot) {
    bool match = true;
    for (auto &kv : templ) {
      auto *attr = obj->findAttribute(kv.first);
      if (!attr || *attr != kv.second) { match = false; break; }
    }
    if (match) {
      std::shared_lock<std::shared_mutex> lock2(v_mutex_);
      if (idx >= v_table_.size() || v_table_[idx].v_is_free || !v_table_[idx].v_object) continue;
      if (v_table_[idx].v_object.get() != obj.get()) continue;
      uint32_t ver = v_table_[idx].v_version.load(std::memory_order_acquire);
      out.push_back(v_compose_handle(idx, ver));
    }
  }
  return out;
}

std::vector<CK_OBJECT_HANDLE> v_ObjectStore_M1::v_all_handles() const {
  std::shared_lock<std::shared_mutex> lock(v_mutex_);
  std::vector<CK_OBJECT_HANDLE> out;
  out.reserve(v_table_.size());
  for (size_t i = 0; i < v_table_.size(); ++i) {
    if (!v_table_[i].v_is_free && v_table_[i].v_object) {
      uint32_t ver = v_table_[i].v_version.load(std::memory_order_acquire);
      out.push_back(v_compose_handle(i, ver));
    }
  }
  return out;
}

void v_ObjectStore_M1::v_reindex(CK_OBJECT_HANDLE handle) {
  std::unique_lock<std::shared_mutex> lock(v_mutex_);
  uint32_t index = v_extract_index(handle);
  uint32_t version = v_extract_version(handle);
  if (index >= v_table_.size() || v_table_[index].v_is_free || !v_table_[index].v_object) return;
  if (v_table_[index].v_version.load(std::memory_order_acquire) != version) return;
  // Remove old entries and re-insert current state
  // We need to know old values, but we can just remove all entries for this index
  // by scanning indices (O(k) where k is bucket size for each map)
  // First, remove any existing entries for this index from all maps
  for (auto it = v_label_index_.begin(); it != v_label_index_.end(); ) {
    if (it->second == index) it = v_label_index_.erase(it);
    else ++it;
  }
  for (auto it = v_id_index_.begin(); it != v_id_index_.end(); ) {
    if (it->second == index) it = v_id_index_.erase(it);
    else ++it;
  }
  for (auto it = v_class_index_.begin(); it != v_class_index_.end(); ) {
    if (it->second == index) it = v_class_index_.erase(it);
    else ++it;
  }
  v_index_insert(index, v_table_[index].v_object.get());
}

} // namespace vhsm::keystore::internal
