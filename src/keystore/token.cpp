#include "token.h"

namespace vhsm::keystore {

Token::Token(const std::string& label, const std::string& id)
    : v_clock_()
    , v_core_(label, id, v_clock_)
{
}

Token::~Token() = default;

const std::string& Token::get_label() const noexcept {
    return v_core_.v_get_label();
}

const std::string& Token::get_id() const noexcept {
    return v_core_.v_get_id();
}

CK_ULONG Token::get_max_session_count() const noexcept {
    return v_core_.v_get_max_session_count();
}

CK_ULONG Token::get_session_count() const noexcept {
    return v_core_.v_get_session_count();
}

CK_ULONG Token::get_max_rw_session_count() const noexcept {
    return v_core_.v_get_max_rw_session_count();
}

CK_ULONG Token::get_rw_session_count() const noexcept {
    return v_core_.v_get_rw_session_count();
}

CK_BBOOL Token::is_token_initialized() const noexcept {
    return v_core_.v_is_token_initialized();
}

CK_BBOOL Token::is_user_pin_set() const noexcept {
    return v_core_.v_is_user_pin_set();
}

CK_BBOOL Token::is_so_pin_set() const noexcept {
    return v_core_.v_is_so_pin_set();
}

CK_BBOOL Token::is_user_login_required() const noexcept {
    return v_core_.v_is_user_login_required();
}

CK_BBOOL Token::is_so_login_required() const noexcept {
    return v_core_.v_is_so_login_required();
}

std::shared_ptr<HsmObject> Token::get_object(CK_OBJECT_HANDLE handle) {
    return v_core_.v_get_object(handle);
}

std::shared_ptr<const HsmObject> Token::get_object(CK_OBJECT_HANDLE handle) const {
    return v_core_.v_get_object(handle);
}

bool Token::destroy_object(CK_OBJECT_HANDLE handle) {
    return v_core_.v_destroy_object(handle);
}

std::vector<std::uint8_t> Token::get_kek() const {
    return v_core_.v_get_kek();
}

// --- PIN management: validate raw input, then delegate to the core ---
// A null pointer with a non-zero length is always invalid (CKR_ARGUMENTS_BAD).
// Length-range and correctness checks are the core's responsibility.
//
// WHY consistent null-check pattern: For every PIN method, we check:
// (ptr == nullptr && len > 0) => INVALID. This prevents buffer overruns and
// catches C API mistakes (caller passed nullptr by accident). The core then
// validates length ranges and cryptographic correctness.

CK_RV Token::initialize_user_pin(const CK_CHAR* pin, CK_ULONG pinLen) {
    if (pin == nullptr && pinLen > 0) return CKR_ARGUMENTS_BAD;
    return v_core_.v_initialize_user_pin(pin, pinLen);
}

CK_RV Token::initialize_so_pin(const CK_CHAR* pin, CK_ULONG pinLen) {
    if (pin == nullptr && pinLen > 0) return CKR_ARGUMENTS_BAD;
    return v_core_.v_initialize_so_pin(pin, pinLen);
}

CK_RV Token::set_user_pin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen) {
    if ((oldPin == nullptr && oldLen > 0) || (newPin == nullptr && newLen > 0)) {
        return CKR_ARGUMENTS_BAD;
    }
    return v_core_.v_set_user_pin(oldPin, oldLen, newPin, newLen);
}

CK_RV Token::set_so_pin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen) {
    if ((oldPin == nullptr && oldLen > 0) || (newPin == nullptr && newLen > 0)) {
        return CKR_ARGUMENTS_BAD;
    }
    return v_core_.v_set_so_pin(oldPin, oldLen, newPin, newLen);
}

CK_RV Token::verify_user_pin(const CK_CHAR* pin, CK_ULONG pinLen) {
    if (pin == nullptr && pinLen > 0) return CKR_ARGUMENTS_BAD;
    return v_core_.v_verify_user_pin(pin, pinLen);
}

CK_RV Token::verify_so_pin(const CK_CHAR* pin, CK_ULONG pinLen) {
    if (pin == nullptr && pinLen > 0) return CKR_ARGUMENTS_BAD;
    return v_core_.v_verify_so_pin(pin, pinLen);
}

CK_RV Token::change_user_pin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen) {
    if ((oldPin == nullptr && oldLen > 0) || (newPin == nullptr && newLen > 0)) {
        return CKR_ARGUMENTS_BAD;
    }
    return v_core_.v_change_user_pin(oldPin, oldLen, newPin, newLen);
}

CK_RV Token::change_so_pin(const CK_CHAR* oldPin, CK_ULONG oldLen, const CK_CHAR* newPin, CK_ULONG newLen) {
    if ((oldPin == nullptr && oldLen > 0) || (newPin == nullptr && newLen > 0)) {
        return CKR_ARGUMENTS_BAD;
    }
    return v_core_.v_change_so_pin(oldPin, oldLen, newPin, newLen);
}

CK_RV Token::login(CK_USER_TYPE userType, const CK_CHAR* pin, CK_ULONG pinLen) {
    if (pin == nullptr && pinLen > 0) return CKR_ARGUMENTS_BAD;
    return v_core_.v_login(userType, pin, pinLen);
}

CK_RV Token::logout(CK_USER_TYPE userType) {
    return v_core_.v_logout(userType);
}

void Token::increment_session_count() {
    v_core_.v_increment_session_count();
}

void Token::decrement_session_count() {
    v_core_.v_decrement_session_count();
}

void Token::increment_rw_session_count() {
    v_core_.v_increment_rw_session_count();
}

void Token::decrement_rw_session_count() {
    v_core_.v_decrement_rw_session_count();
}

void Token::restore_state(CK_BBOOL token_initialized,
                          CK_BBOOL user_pin_set,
                          CK_BBOOL so_pin_set,
                          CK_BBOOL user_login_required,
                          CK_BBOOL so_login_required,
                          unsigned max_failed_attempts,
                          unsigned user_failed_attempts,
                          unsigned so_failed_attempts,
                          CK_BBOOL user_pin_locked,
                          CK_BBOOL so_pin_locked,
                          const std::vector<uint8_t>& kek) {
    v_core_.v_restore_state(token_initialized, user_pin_set, so_pin_set,
                            user_login_required, so_login_required,
                            max_failed_attempts, user_failed_attempts,
                            so_failed_attempts, user_pin_locked, so_pin_locked,
                            kek);
}

} // namespace vhsm::keystore
