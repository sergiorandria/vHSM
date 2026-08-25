#ifndef VHSM_KEYSTORE_OBJECT_STORE_H
#define VHSM_KEYSTORE_OBJECT_STORE_H

#include "../domain/core/kernel_types.h"
#include "../domain/pkcs11/pkcs11_types.h"
#include "hsm_object.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace vhsm::keystore::internal {

/**
 * ObjectStore manages HSM objects and their handles.
 * Implements handle allocation similar to a GDT (Global Descriptor Table)
 * where each valid object gets a unique CK_OBJECT_HANDLE.
 *
 * The handle is essentially an index into an internal table, with
 * additional bits for version tracking to prevent handle reuse attacks.
 *
 * WHY a handle-based API (not pointers): PKCS#11 is a C API; returning raw
 * pointers to C code is dangerous (caller might use it after free, or share it
 * across processes). Handles are indices that we validate on every access,
 * so we can catch use-after-free and return CKR_OBJECT_HANDLE_INVALID instead.
 *
 * WHY version bits: If an object is deleted and its slot reused for a new
 * object, old handles to the deleted object must become invalid. Version bits
 * increment each time a slot is reused, so old (version, index) pairs no longer
 * match. This prevents a subtle class of bugs where stale handles seem valid.
 *
 * WHY std::shared_ptr<HsmObject>: Objects are owned by the store (one strong
 * reference per entry) but v_get_object/v_create_object/v_find_object_if hand
 * out additional strong references so the object stays alive for the duration
 * of the caller's C_* operation even if another thread destroys the handle
 * concurrently. The store's own reference is what grants/denies future lookups;
 * external references pin the object in memory past destruction.
 */
class v_ObjectStore_M1 {
public:
  v_ObjectStore_M1();
  ~v_ObjectStore_M1();

  // WHY non-copyable: Each ObjectStore owns a unique set of objects. Copying
  // would duplicate all objects and violate ownership semantics (who frees
  // them?). Non-copyable enforces that there's exactly one authoritative store
  // per token.
  v_ObjectStore_M1(const v_ObjectStore_M1 &) = delete;
  v_ObjectStore_M1 &operator=(const v_ObjectStore_M1 &) = delete;

  // WHY template v_create_object: We want type-safe creation of derived types
  // (e.g., PrivateKey, Certificate). Returning a shared_ptr<T> instead of T*
  // lets callers avoid casts AND keeps the object alive for the caller. The
  // template is instantiated at compile time for each T, so no runtime
  // overhead.
  template <typename T, typename... Args>
  std::pair<CK_OBJECT_HANDLE, std::shared_ptr<T>>
  v_create_object(Args &&...args);

  // WHY nodiscard: A caller that ignores the handle can't access the object
  // again. Forgetting to capture the handle is almost always a bug.
  // [[nodiscard]] makes the compiler warn about silently-discarded handles.
  [[nodiscard]]
  std::shared_ptr<HsmObject> v_get_object(CK_OBJECT_HANDLE handle);

  [[nodiscard]]
  std::shared_ptr<const HsmObject> v_get_object(CK_OBJECT_HANDLE handle) const;

  // WHY bool v_destroy_object returns true/false instead of CKR_*: Destruction
  // is straightforward (mark slot free). Returning bool is simpler: true =
  // destroyed, false = handle invalid. The Token layer can map this to PKCS#11
  // error codes. This drops the store's own strong reference; callers that
  // already hold a shared_ptr (from
  // v_get_object/v_create_object/v_find_object_if) keep the object alive until
  // they release it, preventing use-after-free.
  bool v_destroy_object(CK_OBJECT_HANDLE handle);

  size_t v_get_object_count() const;

  bool v_is_valid_handle(CK_OBJECT_HANDLE handle) const;

  // WHY template v_find_object_if with Predicate: Search is decoupled from
  // storage. Callers define what "found" means (predicate: lambda, function
  // ptr) without the store knowing about specific attributes. This makes search
  // flexible: find by label, by ID, by cryptographic key, etc., all with the
  // same code.
  //
  // WHY returns (handle, shared_ptr) pair: Caller needs both. The handle is
  // opaque and required for future operations (get, delete). The shared_ptr
  // lets callers immediately use the object AND keeps it alive for the caller's
  // operation.
  //
  // Optimized: uses secondary index for CKA_CLASS/CKA_LABEL/CKA_ID when
  // predicate is of that form; otherwise falls back to linear scan.
  // Lock is shared for readers, and predicate is evaluated outside the lock
  // on a snapshot to minimize hold time.
  template <typename Predicate>
  std::pair<CK_OBJECT_HANDLE, std::shared_ptr<HsmObject>>
  v_find_object_if(Predicate pred) const {
    // Fast path: try indexed lookup if predicate is attribute equality.
    // We detect this via overloads for common patterns below.
    // For generic predicate, we do shared lock + snapshot.
    std::shared_lock<std::shared_mutex> lock(v_mutex_);
    // Snapshot candidates to evaluate outside lock
    std::vector<std::pair<uint32_t, std::shared_ptr<HsmObject>>> snapshot;
    snapshot.reserve(v_table_.size());
    for (size_t i = 0; i < v_table_.size(); ++i) {
      if (!v_table_[i].v_is_free && v_table_[i].v_object) {
        snapshot.emplace_back(i, v_table_[i].v_object);
      }
    }
    lock.unlock();
    for (auto &[idx, obj] : snapshot) {
      if (pred(obj.get())) {
        std::shared_lock<std::shared_mutex> lock2(v_mutex_);
        if (idx >= v_table_.size() || v_table_[idx].v_is_free || !v_table_[idx].v_object)
          continue;
        // Re-validate version after re-lock
        uint32_t version = v_table_[idx].v_version.load(std::memory_order_acquire);
        // Need to ensure object still same
        if (v_table_[idx].v_object.get() != obj.get())
          continue;
        CK_OBJECT_HANDLE handle = v_compose_handle(idx, version);
        return {handle, obj};
      }
    }
    return {CK_INVALID_HANDLE, nullptr};
  }

  // Optimized find by exact attributes using secondary indices.
  // Returns first match or invalid handle. O(1) average for indexed attrs,
  // O(k) where k = bucket size, vs O(n) scan.
  std::pair<CK_OBJECT_HANDLE, std::shared_ptr<HsmObject>>
  v_find_by_attributes(const std::unordered_map<CK_ATTRIBUTE_TYPE, std::vector<uint8_t>> &templ) const;

  // Returns all handles matching template, using indices when possible.
  std::vector<CK_OBJECT_HANDLE>
  v_find_all_by_attributes(const std::unordered_map<CK_ATTRIBUTE_TYPE, std::vector<uint8_t>> &templ) const;

  // Reindex after attribute update (e.g., C_SetAttributeValue on CKA_LABEL/ID)
  void v_reindex(CK_OBJECT_HANDLE handle);

  // Enumerate all live handles (replaces g_objectRegistry)
  [[nodiscard]] std::vector<CK_OBJECT_HANDLE> v_all_handles() const;

private:
  struct v_ObjectEntry {
    // WHY shared_ptr: The store holds one strong reference per live entry.
    // Lookups copy this pointer out so the object survives concurrent
    // destruction by other threads. When the entry is freed (v_destroy_object)
    // or erased, this reference is dropped and the object is reclaimed once
    // external users release theirs.
    std::shared_ptr<HsmObject> v_object;

    // WHY atomic<u32> for version: Version increments each time the slot is
    // reused. Atomic ensures concurrent reads (v_get_object) don't race with
    // version updates.
    std::atomic<uint32_t> v_version;

    // WHY v_is_free flag: Tracks whether this slot is available. If true, the
    // slot is reusable for a new object. This avoids wasting space (we don't
    // shrink the table) and reduces allocation overhead for the common case
    // (reuse existing slot).
    bool v_is_free;

    // Intrusive free-list: when v_is_free, stores index of next free slot.
    // UINT32_MAX = end of list. Allows O(1) alloc/free vs O(n) scan.
    uint32_t v_next_free;

    v_ObjectEntry() : v_version(0), v_is_free(true), v_next_free(UINT32_MAX) {}

    // WHY delete copy for entry: Each entry owns its object (unique_ptr).
    // Copying would duplicate the object, violating ownership. Move is allowed
    // so entries can be repositioned within the table during growth.
    v_ObjectEntry(const v_ObjectEntry &) = delete;
    v_ObjectEntry &operator=(const v_ObjectEntry &) = delete;

    v_ObjectEntry(v_ObjectEntry &&other) noexcept
        : v_object(std::move(other.v_object)),
          v_version(other.v_version.load()), v_is_free(other.v_is_free),
          v_next_free(other.v_next_free) {
      other.v_is_free = true;
      other.v_next_free = UINT32_MAX;
    }

    v_ObjectEntry &operator=(v_ObjectEntry &&other) noexcept {
      if (this != &other) {
        v_object = std::move(other.v_object);
        v_version.store(other.v_version.load());
        v_is_free = other.v_is_free;
        v_next_free = other.v_next_free;
        other.v_is_free = true;
        other.v_next_free = UINT32_MAX;
      }
      return *this;
    }
  };

  // WHY CK_INVALID_HANDLE = 0: By PKCS#11 convention, handle 0 is reserved and
  // invalid. This simplifies null-like checks: if (handle == 0) is reliable.
  // All valid handles are >= 1.
  static constexpr CK_OBJECT_HANDLE CK_INVALID_HANDLE = 0;

  // WHY extract/compose functions: Handles are opaque to callers but internally
  // encode (index, version). These helpers separate the concern of handle
  // packing/ unpacking from the core logic. Makes it easy to change handle
  // layout later.
  static uint32_t v_extract_index(CK_OBJECT_HANDLE handle);
  static uint32_t v_extract_version(CK_OBJECT_HANDLE handle);
  static CK_OBJECT_HANDLE v_compose_handle(uint32_t index, uint32_t version);

  // WHY v_table_: Dynamic array of object entries. Grows as needed; slots are
  // reused (marked free). This is cache-friendly and avoids hash table
  // overhead.
  std::vector<v_ObjectEntry> v_table_;

  // WHY shared_mutex: Many concurrent v_get_object/v_find_object_if readers,
  // rarer create/destroy writers. shared_mutex allows parallel reads.
  mutable std::shared_mutex v_mutex_;

  // Intrusive free-list head: index of first free slot, or UINT32_MAX if none.
  // Protected by v_mutex_ (exclusive).
  uint32_t v_free_head_ = UINT32_MAX;

  // Secondary indices for hot attributes. Protected by v_mutex_.
  // Key -> vector of table indices (multimap because duplicate labels/IDs allowed)
  std::unordered_multimap<std::string, uint32_t> v_label_index_;
  std::unordered_multimap<std::string, uint32_t> v_id_index_;
  std::unordered_multimap<uint32_t, uint32_t> v_class_index_;

  // Helpers for index maintenance
  void v_index_insert(uint32_t index, const HsmObject *obj);
  void v_index_remove(uint32_t index, const HsmObject *obj);
  std::string v_extract_label(const HsmObject *obj) const;
  std::string v_extract_id(const HsmObject *obj) const;
  uint32_t v_extract_class(const HsmObject *obj) const;
};

inline constexpr CK_OBJECT_HANDLE CK_INVALID_HANDLE = 0;

} // namespace vhsm::keystore::internal

// Template implementation
//
// WHY template implementation in header: C++ requires template definitions to
// be visible at instantiation sites. Putting v_create_object inline allows the
// compiler to instantiate it for each concrete type (PrivateKey, Certificate,
// etc.) at the call site. This is standard practice and has no runtime cost
// (inlining).
namespace vhsm::keystore::internal {

template <typename T, typename... Args>
std::pair<CK_OBJECT_HANDLE, std::shared_ptr<T>>
v_ObjectStore_M1::v_create_object(Args &&...args) {
  // WHY static_assert: Check at compile time that T derives from HsmObject.
  // This prevents misuse (e.g., v_create_object<int>()) from reaching runtime.
  static_assert(std::is_base_of_v<HsmObject, T>,
                "T must derive from HsmObject");

  std::unique_lock<std::shared_mutex> lock(v_mutex_);

  uint32_t index;
  uint32_t version;
  if (v_free_head_ != UINT32_MAX) {
    // O(1) pop from free-list
    index = v_free_head_;
    v_free_head_ = v_table_[index].v_next_free;
    v_table_[index].v_is_free = false;
    v_table_[index].v_version.fetch_add(1, std::memory_order_relaxed);
    version = v_table_[index].v_version.load(std::memory_order_acquire);
    v_table_[index].v_object =
        std::make_shared<T>(std::forward<Args>(args)...);
    v_index_insert(index, v_table_[index].v_object.get());
    CK_OBJECT_HANDLE handle = v_compose_handle(index, version);
    return {handle, std::static_pointer_cast<T>(v_table_[index].v_object)};
  }

  // Append new entry if no free slot
  index = v_table_.size();
  v_table_.emplace_back();
  v_table_[index].v_is_free = false;
  v_table_[index].v_version.fetch_add(1, std::memory_order_relaxed);
  version = v_table_[index].v_version.load(std::memory_order_acquire);
  v_table_[index].v_object = std::make_shared<T>(std::forward<Args>(args)...);
  v_index_insert(index, v_table_[index].v_object.get());
  CK_OBJECT_HANDLE handle = v_compose_handle(index, version);
  return {handle, std::static_pointer_cast<T>(v_table_[index].v_object)};
}

} // namespace vhsm::keystore::internal

#endif // VHSM_KEYSTORE_OBJECT_STORE_H
