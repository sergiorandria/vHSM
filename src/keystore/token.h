#ifndef VHSM_KEYSTORE_TOKEN_H
#define VHSM_KEYSTORE_TOKEN_H

#include "../core/types.h"
#include "../core/secure_buffer.h"
#include "hsm_object.h"
#include "object_store.h"

#include <string>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <cstring>
#include <atomic>

namespace vhsm::keystore {

class Token {
public:
    Token(const std::string& label, const std::string& id);
    ~Token();

    // Non-copyable
    Token(const Token&) = delete;
    Token& operator=(const Token&) = delete;

    // Getters
    const std::string& get_label() const noexcept;
    const std::string& get_id() const noexcept;
    CK_ULONG get_max_session_count() const noexcept;
    CK_ULONG get_session_count() const noexcept;
    CK_ULONG get_max_rw_session_count() const noexcept;
    CK_ULONG get_rw_session_count() const noexcept;
    CK_BBOOL is_token_initialized() const noexcept;
    CK_BBOOL is_user_pin_set() const noexcept;
    CK_BBOOL is_so_pin_set() const noexcept;
    CK_BBOOL is_user_login_required() const noexcept;
    CK_BBOOL is_so_login_required() const noexcept;

    // NOTE (removed getLoginState()):
    // Login state is inherently per-Session in PKCS#11 (multiple sessions may be
    // logged in independently, possibly as different users). Token only verifies
    // PIN correctness — it has no concept of "is this token currently logged in".
    // The previous getLoginState() always returned CKU_INVALID (a stub) and was
    // misleading API surface. Track login state on the Session class instead.

    // IMPORTANT: createObject is a template and MUST be defined here (inline),
    // not in token.cpp. Template member functions must be visible at the point
    // of instantiation in every translation unit that calls them — otherwise
    // you get "undefined reference" linker errors the moment another .cpp
    // calls token.createObject<SomeType>(...).
    // Locking: ObjectStore::createObject() / destroyObject() are internally
    // synchronized (ObjectStore owns its own std::mutex), so this does not
    // race on object_store_ itself even with a shared_lock. We still take a
    // unique_lock here for two reasons:
    //   1. Forward-compatibility: if Token-level state ever needs to change
    //      alongside object creation/destruction (counters, caches, etc.),
    //      a shared_lock would silently become unsafe.
    //   2. Clarity: "this call mutates token-owned state" is the intent, even
    //      though today the mutation is fully delegated to a self-locking member.
    template<typename T, typename... Args>
    std::pair<CK_OBJECT_HANDLE, T*> create_object(Args&&... args) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        return object_store_.template createObject<T>(std::forward<Args>(args)...);
    }

    HsmObject* get_object(CK_OBJECT_HANDLE handle);
    const HsmObject* get_object(CK_OBJECT_HANDLE handle) const;
    bool destroy_object(CK_OBJECT_HANDLE handle);

    // PIN management
    CK_RV initialize_user_pin(const CK_CHAR* pin, CK_ULONG pinLen);
    CK_RV initialize_so_pin(const CK_CHAR* pin, CK_ULONG pinLen);
    CK_RV set_user_pin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen);
    CK_RV set_so_pin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen);
    CK_RV verify_user_pin(const CK_CHAR* pin, CK_ULONG pinLen);
    CK_RV verify_so_pin(const CK_CHAR* pin, CK_ULONG pinLen);
    CK_RV change_user_pin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen);
    CK_RV change_so_pin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen);
    CK_RV login(CK_USER_TYPE userType, const CK_CHAR* pin, CK_ULONG pinLen);
    CK_RV logout(CK_USER_TYPE userType);

    // Session management (delegated to SlotManager, but token tracks counts)
    void increment_session_count();
    void decrement_session_count();
    void increment_rw_session_count();
    void decrement_rw_session_count();

private:
    // Internal helper: constant-time comparison of a candidate PIN against a
    // stored PIN held in a SecureBuffer. Returns true iff lengths match AND
    // all bytes match, without short-circuiting on the first mismatch
    // (mitigates timing side-channels on PIN verification).
    static bool secure_pin_equals(const SecureBuffer& stored,
                                   std::size_t stored_len,
                                   const CK_CHAR* candidate,
                                   CK_ULONG candidate_len) noexcept;

    std::string label_;
    std::string id_; // Token identifier (CKA_ID)

    // Object store for objects in this token
    ObjectStore object_store_;

    // Session counts
    std::atomic<CK_ULONG> session_count_;
    std::atomic<CK_ULONG> rw_session_count_;

    // Token flags
    std::atomic<CK_BBOOL> token_initialized_;
    std::atomic<CK_BBOOL> user_pin_set_;
    std::atomic<CK_BBOOL> so_pin_set_;
    std::atomic<CK_BBOOL> user_login_required_;
    std::atomic<CK_BBOOL> so_login_required_;

    // PINs.
    //
    // user_pin_ / so_pin_ are fixed-CAPACITY (256-byte) SecureBuffers.
    // SecureBuffer::size() returns the element COUNT (i.e. capacity == 256),
    // NOT the number of meaningful PIN bytes currently stored. The actual
    // stored PIN length is tracked separately in user_pin_len_ / so_pin_len_.
    //
    // Previously, code compared `oldLen != user_pin_.size()` (== 256), which
    // would reject every real-world PIN (PINs are never exactly 256 bytes).
    // All comparisons now use user_pin_len_ / so_pin_len_ instead.
    SecureBuffer user_pin_{256};
    SecureBuffer so_pin_{256};
    std::size_t user_pin_len_{0};
    std::size_t so_pin_len_{0};
    std::mutex user_pin_mutex_;
    std::mutex so_pin_mutex_;

    // Mutex for protecting object store and session counts
    mutable std::shared_mutex mutex_;
};

} // namespace vhsm::keystore

#endif // VHSM_KEYSTORE_TOKEN_H