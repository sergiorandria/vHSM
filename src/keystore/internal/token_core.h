#ifndef VHSM_KEYSTORE_INTERNAL_TOKEN_CORE_H
#define VHSM_KEYSTORE_INTERNAL_TOKEN_CORE_H

#include "../../core/types.h"
#include "../../core/secure_buffer.h"
#include "../../core/hsm_clock.h"

#include "../hsm_object.h"
#include "../object_store.h"
#include "../attribute_store.h"

#include <atomic>
#include <condition_variable>
#include <cstring>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <vector>

namespace vhsm::keystore::internal {

// Internal business-logic core for a Token.
//
// This is the "sophisticated" layer: it owns all Token state and implements
// every operation (PIN management, login, object lifecycle, KEK retrieval,
// session accounting). The public vhsm::keystore::Token is a thin GLIBC-style
// facade that validates raw CK_* inputs, translates them, and delegates here.
//
// Time is supplied via an injected IHsmClock (never std::chrono directly) so
// the logic is deterministic and unit-testable with a FrozenHsmClock.
class v_TokenCore_M1 {
public:
    // `clock` must outlive this core. The public Token owns a SystemHsmClock
    // and passes it here; tests pass a FrozenHsmClock.
    v_TokenCore_M1(const std::string& label,
                   const std::string& id,
                   const IHsmClock& clock);

    ~v_TokenCore_M1();

    // Non-copyable / non-movable (owns atomics, mutexes, SecureBuffers).
    v_TokenCore_M1(const v_TokenCore_M1&) = delete;
    v_TokenCore_M1& operator=(const v_TokenCore_M1&) = delete;

    // --- Identity / status getters ---
    const std::string& v_get_label() const noexcept;
    const std::string& v_get_id() const noexcept;
    CK_ULONG v_get_max_session_count() const noexcept;
    CK_ULONG v_get_session_count() const noexcept;
    CK_ULONG v_get_max_rw_session_count() const noexcept;
    CK_ULONG v_get_rw_session_count() const noexcept;
    CK_BBOOL v_is_token_initialized() const noexcept;
    CK_BBOOL v_is_user_pin_set() const noexcept;
    CK_BBOOL v_is_so_pin_set() const noexcept;
    CK_BBOOL v_is_user_login_required() const noexcept;
    CK_BBOOL v_is_so_login_required() const noexcept;

    // --- Object lifecycle (delegated to the internal object store) ---
    template <typename T, typename... Args>
    std::pair<CK_OBJECT_HANDLE, T*> v_create_object(Args&&... args) {
        std::unique_lock<std::shared_mutex> lock(v_mutex_);
        return v_object_store_.template v_create_object<T>(std::forward<Args>(args)...);
    }

    template <typename T>
    T* v_find_object_by_label_and_id(const std::string& label, const std::string& id) {
        auto result = v_object_store_.v_find_object_if(
            [&](HsmObject* obj) {
                v_AttributeStore_M1 attr_store(*obj);
                std::vector<u8> label_value;
                CK_ULONG label_len = 0;
                CK_RV rv = attr_store.v_get_attribute(CKA_LABEL, nullptr, &label_len);
                if (rv != CKR_OK) return false;
                label_value.resize(label_len);
                rv = attr_store.v_get_attribute(CKA_LABEL, label_value.data(), &label_len);
                if (rv != CKR_OK) return false;

                std::vector<u8> id_value;
                CK_ULONG id_len = 0;
                rv = attr_store.v_get_attribute(CKA_ID, nullptr, &id_len);
                if (rv != CKR_OK) return false;
                id_value.resize(id_len);
                rv = attr_store.v_get_attribute(CKA_ID, id_value.data(), &id_len);
                if (rv != CKR_OK) return false;

                std::string obj_label(reinterpret_cast<char*>(label_value.data()), label_len);
                std::string obj_id(reinterpret_cast<char*>(id_value.data()), id_len);
                if (obj_label != label || obj_id != id) return false;
                return true;
            });
        if (result.second) return static_cast<T*>(result.second);
        return nullptr;
    }

    std::shared_ptr<HsmObject> v_get_object(CK_OBJECT_HANDLE handle);
    std::shared_ptr<const HsmObject> v_get_object(CK_OBJECT_HANDLE handle) const;
    bool v_destroy_object(CK_OBJECT_HANDLE handle);

    // Retrieve the Key Encryption Key (KEK) used for wrapping/unwrapping.
    std::vector<std::uint8_t> v_get_kek() const;

    // --- PIN / login (CK_RV return codes; no exceptions for expected errors) ---
    CK_RV v_initialize_user_pin(const CK_CHAR* pin, CK_ULONG pinLen);
    CK_RV v_initialize_so_pin(const CK_CHAR* pin, CK_ULONG pinLen);
    CK_RV v_set_user_pin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen);
    CK_RV v_set_so_pin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen);
    CK_RV v_verify_user_pin(const CK_CHAR* pin, CK_ULONG pinLen);
    CK_RV v_verify_so_pin(const CK_CHAR* pin, CK_ULONG pinLen);
    CK_RV v_change_user_pin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen);
    CK_RV v_change_so_pin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen);
    CK_RV v_login(CK_USER_TYPE userType, const CK_CHAR* pin, CK_ULONG pinLen);
    CK_RV v_logout(CK_USER_TYPE userType);

    // --- Session accounting ---
    void v_increment_session_count();
    void v_decrement_session_count();
    void v_increment_rw_session_count();
    void v_decrement_rw_session_count();

    // Last PIN operation timestamp (wall-clock via injected IHsmClock).
    // Exposed for auditing / rate-limiting and to make the clock dependency
    // observable in tests.
    HsmTimePoint v_last_pin_op_at() const noexcept;

    // --- PIN lockout (brute-force protection) ---
    // The plan specifies a failed-attempt lockout counter (see PLAN.md
    // "PIN brute force").  Each failed verification increments the counter;
    // once it reaches the threshold the PIN is locked and further attempts
    // return CKR_PIN_LOCKED.  A successful verification resets the counter.
    void v_set_max_failed_attempts(unsigned max);
    unsigned v_max_failed_attempts() const noexcept;
    CK_BBOOL v_is_user_pin_locked() const noexcept;
    CK_BBOOL v_is_so_pin_locked() const noexcept;
    unsigned v_user_failed_attempts() const noexcept;
    unsigned v_so_failed_attempts() const noexcept;

private:
    // Constant-time PIN comparison (see token.cpp for rationale).
    static bool v_secure_pin_equals(const SecureBuffer& stored,
                                    std::size_t stored_len,
                                    const CK_CHAR* candidate,
                                    CK_ULONG candidate_len) noexcept;

    void v_touch_pin_op() noexcept;

    // Core of PIN verification with lockout bookkeeping.  `counter`, `locked`
    // and `mutex` select the per-role state (user vs SO).
    static CK_RV v_verify_pin_with_lockout(
        const SecureBuffer& stored, std::size_t stored_len,
        const CK_CHAR* candidate, CK_ULONG candidate_len,
        CK_BBOOL pin_set, CK_RV not_initialized_rv, unsigned max_attempts,
        std::atomic<unsigned>& counter, std::atomic<CK_BBOOL>& locked,
        std::mutex& mutex);

    std::string v_label_;
    std::string v_id_;

    v_ObjectStore_M1 v_object_store_;

    std::atomic<CK_ULONG> v_session_count_;
    std::atomic<CK_ULONG> v_rw_session_count_;

    std::atomic<CK_BBOOL> v_token_initialized_;
    std::atomic<CK_BBOOL> v_user_pin_set_;
    std::atomic<CK_BBOOL> v_so_pin_set_;
    std::atomic<CK_BBOOL> v_user_login_required_;
    std::atomic<CK_BBOOL> v_so_login_required_;

    SecureBuffer v_user_pin_{256};
    SecureBuffer v_so_pin_{256};
    std::size_t v_user_pin_len_{0};
    std::size_t v_so_pin_len_{0};
    std::mutex v_user_pin_mutex_;
    std::mutex v_so_pin_mutex_;

    // PKCS#11 defines SO as "Security Officer"; its PIN also gets lockout
    // protection so an intruder cannot brute-force admin access either.
    std::atomic<unsigned> v_user_failed_attempts_{0};
    std::atomic<unsigned> v_so_failed_attempts_{0};
    std::atomic<CK_BBOOL> v_user_pin_locked_{CK_FALSE};
    std::atomic<CK_BBOOL> v_so_pin_locked_{CK_FALSE};
    std::atomic<unsigned> v_max_failed_attempts_{5};

    mutable std::shared_mutex v_mutex_;

    const IHsmClock& v_clock_;
    HsmTimePoint v_last_pin_op_at_;
};

} // namespace vhsm::keystore::internal

#endif // VHSM_KEYSTORE_INTERNAL_TOKEN_CORE_H
