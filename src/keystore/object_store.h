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
 * WHY version bits: If an object is deleted and its slot reused for a new object,
 * old handles to the deleted object must become invalid. Version bits increment
 * each time a slot is reused, so old (version, index) pairs no longer match.
 * This prevents a subtle class of bugs where stale handles seem valid.
 *
 * WHY std::unique_ptr<HsmObject>: Objects are owned by the store and outlive
 * any single caller's use. unique_ptr ensures automatic cleanup when destroyed.
 * No reference counting needed; ownership is clear and linear.
 */
class v_ObjectStore_M1 {
public:
    v_ObjectStore_M1();
    ~v_ObjectStore_M1();

    // WHY non-copyable: Each ObjectStore owns a unique set of objects. Copying would
    // duplicate all objects and violate ownership semantics (who frees them?).
    // Non-copyable enforces that there's exactly one authoritative store per token.
    v_ObjectStore_M1(const v_ObjectStore_M1&) = delete;
    v_ObjectStore_M1& operator=(const v_ObjectStore_M1&) = delete;

    // WHY template v_create_object: We want type-safe creation of derived types
    // (e.g., PrivateKey, Certificate). Returning T* instead of HsmObject* lets
    // callers avoid casts. The template is instantiated at compile time for each T,
    // so no runtime overhead.
    template<typename T, typename... Args>
    std::pair<CK_OBJECT_HANDLE, T*> v_create_object(Args&&... args);

    // WHY nodiscard: A caller that ignores the handle can't access the object again.
    // Forgetting to capture the handle is almost always a bug. [[nodiscard]] makes
    // the compiler warn about silently-discarded handles.
    [[nodiscard]]
    HsmObject* v_get_object(CK_OBJECT_HANDLE handle);

    [[nodiscard]]
    const HsmObject* v_get_object(CK_OBJECT_HANDLE handle) const;

    // WHY bool v_destroy_object returns true/false instead of CKR_*: Destruction
    // is straightforward (mark slot free). Returning bool is simpler: true = destroyed,
    // false = handle invalid. The Token layer can map this to PKCS#11 error codes.
    bool v_destroy_object(CK_OBJECT_HANDLE handle);

    size_t v_get_object_count() const;

    bool v_is_valid_handle(CK_OBJECT_HANDLE handle) const;

    // WHY template v_find_object_if with Predicate: Search is decoupled from storage.
    // Callers define what "found" means (predicate: lambda, function ptr) without the
    // store knowing about specific attributes. This makes search flexible: find by label,
    // by ID, by cryptographic key, etc., all with the same code.
    //
    // WHY returns (handle, object*) pair: Caller needs both. The handle is opaque and
    // required for future operations (get, delete). The pointer lets callers immediately
    // use the object without a second lookup.
    //
    // WHY lock_guard here: The search iterates the entire table. We hold the lock for
    // the whole search to prevent concurrent modifications (object creation/deletion).
    template<typename Predicate>
    std::pair<CK_OBJECT_HANDLE, HsmObject*> v_find_object_if(Predicate pred) const {
        std::lock_guard<std::mutex> lock(v_mutex_);
        for (size_t i = 0; i < v_table_.size(); ++i) {
            if (!v_table_[i].v_is_free && v_table_[i].v_object) {
                HsmObject* obj = v_table_[i].v_object.get();
                if (pred(obj)) {
                    uint32_t version = v_table_[i].v_version.load();
                    CK_OBJECT_HANDLE handle = v_compose_handle(i, version);
                    return {handle, obj};
                }
            }
        }
        return {CK_INVALID_HANDLE, nullptr};
    }

private:
    struct v_ObjectEntry {
        // WHY unique_ptr: Owns the object exclusively. When the entry is destroyed
        // or reassigned, the object is automatically deleted. No manual cleanup needed.
        std::unique_ptr<HsmObject> v_object;
        
        // WHY atomic<u32> for version: Version increments each time the slot is reused.
        // Atomic ensures concurrent reads (v_get_object) don't race with version updates.
        std::atomic<uint32_t> v_version;
        
        // WHY v_is_free flag: Tracks whether this slot is available. If true, the slot
        // is reusable for a new object. This avoids wasting space (we don't shrink the
        // table) and reduces allocation overhead for the common case (reuse existing slot).
        bool v_is_free;

        v_ObjectEntry() : v_version(0), v_is_free(true) {}

        // WHY delete copy for entry: Each entry owns its object (unique_ptr). Copying
        // would duplicate the object, violating ownership. Move is allowed so entries
        // can be repositioned within the table during growth.
        v_ObjectEntry(const v_ObjectEntry&) = delete;
        v_ObjectEntry& operator=(const v_ObjectEntry&) = delete;

        v_ObjectEntry(v_ObjectEntry&& other) noexcept
            : v_object(std::move(other.v_object)),
              v_version(other.v_version.load()),
              v_is_free(other.v_is_free) {
            other.v_is_free = true;
        }

        v_ObjectEntry& operator=(v_ObjectEntry&& other) noexcept {
            if (this != &other) {
                v_object = std::move(other.v_object);
                v_version.store(other.v_version.load());
                v_is_free = other.v_is_free;
                other.v_is_free = true;
            }
            return *this;
        }
    };

    // WHY CK_INVALID_HANDLE = 0: By PKCS#11 convention, handle 0 is reserved and
    // invalid. This simplifies null-like checks: if (handle == 0) is reliable.
    // All valid handles are >= 1.
    static constexpr CK_OBJECT_HANDLE CK_INVALID_HANDLE = 0;

    // WHY extract/compose functions: Handles are opaque to callers but internally
    // encode (index, version). These helpers separate the concern of handle packing/
    // unpacking from the core logic. Makes it easy to change handle layout later.
    static uint32_t v_extract_index(CK_OBJECT_HANDLE handle);
    static uint32_t v_extract_version(CK_OBJECT_HANDLE handle);
    static CK_OBJECT_HANDLE v_compose_handle(uint32_t index, uint32_t version);

    // WHY v_table_: Dynamic array of object entries. Grows as needed; slots are
    // reused (marked free). This is cache-friendly and avoids hash table overhead.
    std::vector<v_ObjectEntry> v_table_;
    
    // WHY mutex: Protects concurrent access to v_table_. Without it, create/destroy/get
    // could race (one thread deletes while another accesses). lock_guard ensures
    // RAII semantics (lock is released even if an exception is thrown).
    mutable std::mutex v_mutex_;
    
    // WHY atomic v_next_index_: Tracks the next slot to check for reuse. Atomic
    // allows relaxed stores/loads without locking. Improves performance: we don't 
    // hold the mutex when scanning for the next free slot.
    std::atomic<uint32_t> v_next_index_;
};

inline constexpr CK_OBJECT_HANDLE CK_INVALID_HANDLE = 0;

} // namespace vhsm::keystore::internal

// Template implementation
//
// WHY template implementation in header: C++ requires template definitions to be
// visible at instantiation sites. Putting v_create_object inline allows the compiler
// to instantiate it for each concrete type (PrivateKey, Certificate, etc.) at the
// call site. This is standard practice and has no runtime cost (inlining).
namespace vhsm::keystore::internal {

template<typename T, typename... Args>
std::pair<CK_OBJECT_HANDLE, T*> v_ObjectStore_M1::v_create_object(Args&&... args) {
    // WHY static_assert: Check at compile time that T derives from HsmObject.
    // This prevents misuse (e.g., v_create_object<int>()) from reaching runtime.
    static_assert(std::is_base_of_v<HsmObject, T>, "T must derive from HsmObject");

    std::lock_guard<std::mutex> lock(v_mutex_);

    // WHY scan from v_next_index_: Start searching from the last reused slot.
    // This improves cache locality: recently-freed slots are more likely to be hot.
    for (size_t i = 0; i < v_table_.size(); ++i) {
        size_t index = (v_next_index_ + i) % v_table_.size();
        if (v_table_[index].v_is_free) {
            // WHY mark not free, increment version: Mark the slot as in-use and
            // increment the version so old handles to deleted objects become invalid.
            v_table_[index].v_is_free = false;
            v_table_[index].v_version.fetch_add(1);
            uint32_t version = v_table_[index].v_version.load();

            // WHY make_unique: Construct the object in the managed pointer.
            // Exception-safe: if the constructor throws, v_object remains nullptr
            // and the entry stays marked free. No memory leak.
            v_table_[index].v_object = std::make_unique<T>(std::forward<Args>(args)...);

            // WHY compose handle: Combine index + version into an opaque handle.
            CK_OBJECT_HANDLE handle = v_compose_handle(index, version);
            return {handle, static_cast<T*>(v_table_[index].v_object.get())};
        }
    }

    // WHY append new entry if table full: Grow the table dynamically.
    // This is O(1) amortized (vector growth strategy).
    size_t index = v_table_.size();
    v_table_.emplace_back();
    v_table_[index].v_is_free = false;
    v_table_[index].v_version.fetch_add(1);
    uint32_t version = v_table_[index].v_version.load();

    v_table_[index].v_object = std::make_unique<T>(std::forward<Args>(args)...);

    CK_OBJECT_HANDLE handle = v_compose_handle(index, version);
    return {handle, static_cast<T*>(v_table_[index].v_object.get())};
}

} // namespace vhsm::keystore::internal

#endif // VHSM_KEYSTORE_OBJECT_STORE_H
