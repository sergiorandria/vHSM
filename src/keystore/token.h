#ifndef VHSM_KEYSTORE_TOKEN_H
#define VHSM_KEYSTORE_TOKEN_H

#include "../core/secure_buffer.h"
#include "../core/types.h"
#include "../core/system_hsm_clock.h"
#include "attribute_store.h"
#include "hsm_object.h"
#include "object_store.h"
#include "internal/token_core.h"

#include <atomic>
#include <condition_variable>
#include <cstring>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <vector>

namespace vhsm::keystore
{

// WHY Token is a public GLIBC-style facade: PKCS#11 is a C API; Token bridges
// from C (raw pointers, error codes) to C++ (exceptions, smart pointers). This
// layer does raw input validation (null checks, length bounds) and delegates all
// business logic to v_TokenCore_M1. Separating concerns this way makes it easy to
// test the core in isolation and easier to port to other languages later.
//
// WHY Token is non-copyable: Each Token manages identity (label, id) and shared state
// (session counts). Copying would violate uniqueness constraints (two tokens with 
// the same label could exist, breaking invariants). Non-copyable forces callers to
// use shared_ptr or references, preventing accidental duplication.
//
// WHY input validation happens here, not in the core: The core focuses on PKCS#11
// semantics and state. Facade handles C API quirks (null pointers, length mismatches).
// This layering keeps the core clean and easier to reason about.
//
// Public, GLIBC-style facade for a Token.
//
// This layer ONLY validates raw CK_* inputs (null pointers, obvious length /
// range problems) and forwards to the internal business-logic core
// (vhsm::keystore::internal::v_TokenCore_M1). All state and semantics live in
// the core; this class holds no logic of its own beyond input checks.
class Token
{
public:
    // WHY separate constructor takes label + id: PKCS#11 tokens are identified
    // by label (human-readable name) and id (binary identifier). Both must be set
    // at construction and are immutable. Passing them to the constructor makes this
    // constraint explicit and prevents partially-initialized tokens from escaping.
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

    // NOTE (removed getLoginState()): login state is per-Session in PKCS#11.
    // Token only verifies PIN correctness. Track login state on Session.

    // WHY template methods here (not just core): create_object and find_object_by_label_and_id
    // are templates that return typed shared_ptr to derived HsmObject classes (e.g.,
    // std::shared_ptr<PrivateKey>). Templates can't be virtual, so we implement them as
    // thin wrappers that forward to core. This keeps the template instantiation in one
    // place and maintains the facade pattern.
    template <typename T, typename... Args> std::pair<CK_OBJECT_HANDLE, std::shared_ptr<T>> create_object(Args&&... args)
    {
        return v_core_.v_create_object<T>(std::forward<Args>(args)...);
    }

    template <typename T> std::shared_ptr<T> find_object_by_label_and_id(const std::string& label, const std::string& id)
    {
        return v_core_.v_find_object_by_label_and_id<T>(label, id);
    }

    std::shared_ptr<HsmObject> get_object(CK_OBJECT_HANDLE handle);
    std::shared_ptr<const HsmObject> get_object(CK_OBJECT_HANDLE handle) const;
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

    // PIN lockout state (brute-force protection).  A locked PIN rejects all
    // further attempts with CKR_PIN_LOCKED; successful verification or a
    // successful PIN re-initialization/change clears the lock.
    CK_BBOOL is_user_pin_locked() const noexcept { return v_core_.v_is_user_pin_locked(); }
    CK_BBOOL is_so_pin_locked()  const noexcept { return v_core_.v_is_so_pin_locked(); }
    unsigned user_pin_failed_attempts() const noexcept { return v_core_.v_user_failed_attempts(); }
    unsigned so_pin_failed_attempts()  const noexcept { return v_core_.v_so_failed_attempts(); }
    void set_max_pin_attempts(unsigned max) { v_core_.v_set_max_failed_attempts(max); }
    unsigned max_pin_attempts() const noexcept { return v_core_.v_max_failed_attempts(); }

    // Session accounting (delegated to core).
    void increment_session_count();
    void decrement_session_count();
    void increment_rw_session_count();
    void decrement_rw_session_count();

    // Restores persisted token state (Backup/Restore, vault load-on-init).
    // See v_TokenCore_M1::v_restore_state.  Values come from our own
    // TokenSerializer output, so input validation is minimal here.
    void restore_state(CK_BBOOL token_initialized,
                       CK_BBOOL user_pin_set,
                       CK_BBOOL so_pin_set,
                       CK_BBOOL user_login_required,
                       CK_BBOOL so_login_required,
                       unsigned max_failed_attempts,
                       unsigned user_failed_attempts,
                       unsigned so_failed_attempts,
                       CK_BBOOL user_pin_locked,
                       CK_BBOOL so_pin_locked,
                       const std::vector<uint8_t>& kek);

    // WHY NOTE on getLoginState: In PKCS#11, login state is PER-SESSION, not per-token.
    // Different sessions can have different login states. The Token only verifies PIN
    // correctness. The Session object tracks who is logged in (if anyone). This boundary
    // prevents the Token from holding login state it doesn't own, keeping concerns separate.

    // WHY get_kek() is accessible: The KeyWrap object needs the KEK to wrap/unwrap keys.
    // The core generates and stores the KEK; we expose it here for the rest of the system.
    // It's read-only (const method, const return). The caller must not modify it.
    std::vector<std::uint8_t> get_kek() const;

private:
    // WHY SystemHsmClock here (not injected): Tests construct the core directly with
    // FrozenHsmClock for deterministic time. The public Token always uses the system
    // clock. This layering lets tests mock time while production uses real time without
    // cluttering the public interface with a clock parameter.
    vhsm::SystemHsmClock v_clock_;
    
    // WHY v_core_ is the real implementation: All state, locking, object management,
    // and PKCS#11 semantics live in the core. Token is just a thin validation + delegation layer.
    vhsm::keystore::internal::v_TokenCore_M1 v_core_;
};

} // namespace vhsm::keystore

#endif // VHSM_KEYSTORE_TOKEN_H
